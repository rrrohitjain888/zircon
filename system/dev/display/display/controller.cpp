// Copyright 2018 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <ddk/debug.h>
#include <fbl/auto_lock.h>
#include <lib/async/cpp/task.h>
#include <zircon/device/display-controller.h>

#include "controller.h"
#include "client.h"
#include "fuchsia/display/c/fidl.h"

namespace {

void on_displays_changed(void* ctx, uint64_t* displays_added, uint32_t added_count,
                         uint64_t* displays_removed, uint32_t removed_count) {
    static_cast<display::Controller*>(ctx)->OnDisplaysChanged(
            displays_added, added_count, displays_removed, removed_count);
}

void on_display_vsync(void* ctx, uint64_t display, void** handles, uint32_t handle_count) {
    static_cast<display::Controller*>(ctx)->OnDisplayVsync(display, handles, handle_count);
}

display_controller_cb_t dc_cb = {
    .on_displays_changed = on_displays_changed,
    .on_display_vsync = on_display_vsync,
};

} // namespace

namespace display {

void Controller::OnDisplaysChanged(uint64_t* displays_added, uint32_t added_count,
                                   uint64_t* displays_removed, uint32_t removed_count) {
    const DisplayInfo* added_success[added_count];
    int32_t added_success_count = 0;
    uint64_t removed_success[removed_count];
    int32_t removed_success_count = 0;

    fbl::AutoLock lock(&mtx_);
    for (unsigned i = 0; i < removed_count; i++) {
        auto target = displays_.erase(displays_removed[i]);
        if (target) {
            removed_success[removed_success_count++] = displays_removed[i];

            while (!target->images.is_empty()) {
                auto image = target->images.pop_front();
                image->StartRetire();
                image->OnRetire();
            }
        } else {
            zxlogf(TRACE, "Unknown display %ld removed\n", displays_removed[i]);
        }
    }

    for (unsigned i = 0; i < added_count; i++) {
        fbl::AllocChecker ac;
        fbl::unique_ptr<DisplayInfo> info = fbl::make_unique_checked<DisplayInfo>(&ac);
        if (!ac.check()) {
            zxlogf(INFO, "Out of memory when processing display hotplug\n");
            break;
        }
        info->pending_layer_change = false;
        info->layer_count = 0;

        info->id = displays_added[i];
        if (ops_.ops->get_display_info(ops_.ctx, info->id, &info->info) != ZX_OK) {
            zxlogf(TRACE, "Error getting display info for %ld\n", info->id);
            continue;
        }
        if (info->info.edid_present) {
            edid::Edid edid;
            const char* edid_err = "No preferred timing";
            if (!edid.Init(info->info.panel.edid.data, info->info.panel.edid.length, &edid_err)
                    || !edid.GetPreferredTiming(&info->preferred_timing)) {
                zxlogf(TRACE, "Failed to parse edid \"%s\"\n", edid_err);
                continue;
            }
        }

        auto info_ptr = info.get();
        if (displays_.insert_or_find(fbl::move(info))) {
            added_success[added_success_count++] = info_ptr;
        } else {
            zxlogf(INFO, "Ignoring duplicate display\n");
        }
    }

    zx_status_t status;
    if (vc_client_) {
        status = vc_client_->OnDisplaysChanged(added_success, added_success_count,
                                               removed_success, removed_success_count);
        if (status != ZX_OK) {
            zxlogf(INFO, "Error when processing hotplug (%d)\n", status);
        }
    }
    if (primary_client_) {
        status = primary_client_->OnDisplaysChanged(added_success, added_success_count,
                                                    removed_success, removed_success_count);
        if (status != ZX_OK) {
            zxlogf(INFO, "Error when processing hotplug (%d)\n", status);
        }
    }
}

void Controller::OnDisplayVsync(uint64_t display_id, void** handles, uint32_t handle_count) {
    fbl::AutoLock lock(&mtx_);
    DisplayInfo* info = nullptr;
    for (auto& display_config : displays_) {
        if (display_config.id == display_id) {
            info = &display_config;
            break;
        }
    }

    if (!info) {
        return;
    }

    // See ::ApplyConfig for more explaination of how vsync image tracking works.
    //
    // If there's a pending layer change, don't process any present/retire actions
    // until the change is complete.
    if (info->pending_layer_change) {
        if (handle_count != info->layer_count) {
            // There's an unexpected number of layers, so wait until the next vsync.
            return;
        } else if (info->images.is_empty()) {
            // If the images list is empty, then we can't have any pending layers and
            // the change is done when there are no handles being displayed.
            ZX_ASSERT(info->layer_count == 0);
            if (handle_count != 0) {
                return;
            }
        } else {
            // Otherwise the change is done when the last handle_count==info->layer_count
            // images match the handles in the correct order.
            auto iter = --info->images.end();
            int32_t handle_idx = handle_count - 1;
            while (handle_idx >= 0 && iter.IsValid()) {
                if (handles[handle_idx] != iter->info().handle) {
                    break;
                }
                iter--;
                handle_idx--;
            }
            if (handle_idx != -1) {
                return;
            }
        }

        info->pending_layer_change = false;

        if (active_client_ && info->delayed_apply) {
            active_client_->ReapplyConfig();
        }
    }

    // Since we know there are no pending layer changes, we know that every layer (i.e z_index)
    // has an image. So every image either matches a handle (in which case it's being displayed),
    // is older than its layer's image (i.e. in front of in the queue) and can be retired, or is
    // newer than its layer's image (i.e. behind in the queue) and has yet to be presented.
    uint32_t z_indices[handle_count];
    for (unsigned i = 0; i < handle_count; i++) {
        z_indices[i] = UINT32_MAX;
    }
    auto iter = info->images.begin();
    while (iter.IsValid()) {
        auto cur = iter;
        iter++;

        bool handle_match = false;
        bool z_already_matched = false;
        for (unsigned i = 0; i < handle_count; i++) {
            if (handles[i] == cur->info().handle) {
                handle_match = true;
                z_indices[i] = cur->z_index();
                break;
            } else if (z_indices[i] == cur->z_index()) {
                z_already_matched = true;
                break;
            }
        }

        if (!z_already_matched) {
            cur->OnPresent();
            if (!handle_match) {
                info->images.erase(cur)->OnRetire();
            }
        }
    }
}

void Controller::ApplyConfig(DisplayConfig* configs[], int32_t count,
                             bool is_vc, uint32_t client_stamp) {
    const display_config_t* display_configs[count];
    uint32_t display_count = 0;
    {
        fbl::AutoLock lock(&mtx_);
        // The fact that there could already be a vsync waiting to be handled when a config
        // is applied means that a vsync with no handle for a layer could be interpreted as either
        // nothing in the layer has been presented or everything in the layer can be retired. To
        // prevent that ambiguity, we don't allow a layer to be disabled until an image from
        // it has been displayed.
        //
        // Since layers can be moved between displays but the implementation only supports
        // tracking the image in one display's queue, we need to ensure that the old display is
        // done with the a migrated image before the new display is done with it. This means
        // that the new display can't flip until the configuration change is done. However, we
        // don't want to completely prohibit flips, as that would add latency if the layer's new
        // image is being waited for when the configuration is applied.
        //
        // To handle both of these cases, we force all layer changes to complete before the client
        // can apply a new configuration. We allow the client to apply a more complete version of
        // the configuration, although Client::HandleApplyConfig won't migrate a layer's current
        // image if there is also a pending image.
        if (vc_applied_ != is_vc || applied_stamp_ != client_stamp) {
            for (int i = 0; i < count; i++) {
                auto* config = configs[i];
                auto display = displays_.find(config->id);
                if (!display.IsValid()) {
                    continue;
                }

                if (display->pending_layer_change) {
                    display->delayed_apply = true;
                    return;
                }
            }
        }

        for (int i = 0; i < count; i++) {
            auto* config = configs[i];
            auto display = displays_.find(config->id);
            if (!display.IsValid()) {
                continue;
            }

            display->pending_layer_change = config->apply_layer_change() || is_vc != vc_applied_;
            display->layer_count = config->current_layer_count();
            display->delayed_apply = false;

            if (display->layer_count == 0) {
                continue;
            }

            display_configs[display_count++] = config->current_config();

            for (auto& layer_node : config->get_current_layers()) {
                Layer* layer = layer_node.layer;
                fbl::RefPtr<Image> image = layer->current_image();

                // No need to update tracking if there's no image
                if (!image) {
                    continue;
                }

                // Set the image z index so vsync knows what layer the image is in
                image->set_z_index(layer->z_order());
                image->StartPresent();

                // If the image's layer was moved between displays, we need to delete it from the
                // old display's tracking list. The pending_layer_change logic guarantees that the
                // the old display will be done with the image before the new one, so deleting the
                // image won't cause problems.
                // This is also necessary to maintain the guarantee that the last config->current.
                // layer_count elements in the queue are the current images.
                // TODO(stevensd): Convert to list_node_t and use delete
                for (auto& d : displays_) {
                    for (auto& i : d.images) {
                        if (i.info().handle == image->info().handle) {
                            d.images.erase(i);
                            break;
                        }
                    }
                }
                display->images.push_back(fbl::move(image));
            }
        }
    }
    vc_applied_ = is_vc;
    applied_stamp_ = client_stamp;

    ops_.ops->apply_configuration(ops_.ctx, display_configs, display_count);
}

void Controller::ReleaseImage(Image* image) {
    ops_.ops->release_image(ops_.ctx, &image->info());
}

void Controller::SetVcOwner(bool vc_is_owner) {
    fbl::AutoLock lock(&mtx_);
    vc_is_owner_ = vc_is_owner;
    HandleClientOwnershipChanges();
}

void Controller::HandleClientOwnershipChanges() {
    ClientProxy* new_active;
    if (vc_is_owner_ || primary_client_ == nullptr) {
        new_active = vc_client_;
    } else {
        new_active = primary_client_;
    }

    if (new_active != active_client_) {
        if (active_client_) {
            active_client_->SetOwnership(false);
        }
        if (new_active) {
            new_active->SetOwnership(true);
        }
        active_client_ = new_active;
    }
}

void Controller::OnClientDead(ClientProxy* client) {
    fbl::AutoLock lock(&mtx_);
    if (client == vc_client_) {
        vc_client_ = nullptr;
        vc_is_owner_ = false;
    } else if (client == primary_client_) {
        primary_client_ = nullptr;
    }
    HandleClientOwnershipChanges();
}

zx_status_t Controller::DdkOpen(zx_device_t** dev_out, uint32_t flags) {
    return DdkOpenAt(dev_out, "", flags);
}

zx_status_t Controller::DdkOpenAt(zx_device_t** dev_out, const char* path, uint32_t flags) {
    fbl::AutoLock lock(&mtx_);

    bool is_vc = strcmp("virtcon", path) == 0;
    if ((is_vc && vc_client_) || (!is_vc && primary_client_)) {
        zxlogf(TRACE, "Already bound\n");
        return ZX_ERR_ALREADY_BOUND;
    }

    fbl::AllocChecker ac;
    auto client = fbl::make_unique_checked<ClientProxy>(&ac, this, is_vc);
    if (!ac.check()) {
        zxlogf(TRACE, "Failed to alloc client\n");
        return ZX_ERR_NO_MEMORY;
    }

    zx_status_t status = client->Init();
    if (status != ZX_OK) {
        zxlogf(TRACE, "Failed to init client %d\n", status);
        return status;
    }

    // Add all existing displays to the client
    if (displays_.size() > 0) {
        const DisplayInfo* current_displays[displays_.size()];
        int idx = 0;
        for (const DisplayInfo& display : displays_) {
            current_displays[idx++] = &display;
        }
        if ((status = client->OnDisplaysChanged(current_displays, idx, nullptr, 0)) != ZX_OK) {
            zxlogf(TRACE, "Failed to init client %d\n", status);
            return status;
        }
    }

    if ((status = client->DdkAdd(is_vc ? "dc-vc" : "dc", DEVICE_ADD_INSTANCE)) != ZX_OK) {
        zxlogf(TRACE, "Failed to add client %d\n", status);
        return status;
    }

    ClientProxy* client_ptr = client.release();
    *dev_out = client_ptr->zxdev();

    zxlogf(TRACE, "New client connected at \"%s\"\n", path);

    if (is_vc) {
        vc_client_ = client_ptr;
    } else {
        primary_client_ = client_ptr;
    }
    HandleClientOwnershipChanges();

    return ZX_OK;
}

zx_status_t Controller::Bind(fbl::unique_ptr<display::Controller>* device_ptr) {
    zx_status_t status;
    if (device_get_protocol(parent_, ZX_PROTOCOL_DISPLAY_CONTROLLER_IMPL, &ops_)) {
        ZX_DEBUG_ASSERT_MSG(false, "Display controller bind mismatch");
        return ZX_ERR_NOT_SUPPORTED;
    }

    status = loop_.StartThread("display-client-loop", &loop_thread_);
    if (status != ZX_OK) {
        zxlogf(ERROR, "Failed to start loop %d\n", status);
        return status;
    }

    if ((status = DdkAdd("display-controller")) != ZX_OK) {
        zxlogf(ERROR, "Failed to add display core device %d\n", status);
        return status;
    }
    __UNUSED auto ptr = device_ptr->release();

    ops_.ops->set_display_controller_cb(ops_.ctx, this, &dc_cb);

    return ZX_OK;
}

void Controller::DdkUnbind() {
    {
        fbl::AutoLock lock(&mtx_);
        if (vc_client_) {
            vc_client_->Close();
        }
        if (primary_client_) {
            primary_client_->Close();
        }
    }
    DdkRemove();
}

void Controller::DdkRelease() {
    delete this;
}

Controller::Controller(zx_device_t* parent) : ControllerParent(parent) {
    mtx_init(&mtx_, mtx_plain);
}

// ControllerInstance methods

} // namespace display

zx_status_t display_controller_bind(void* ctx, zx_device_t* parent) {
    fbl::AllocChecker ac;
    fbl::unique_ptr<display::Controller> core(new (&ac) display::Controller(parent));
    if (!ac.check()) {
        return ZX_ERR_NO_MEMORY;
    }

    return core->Bind(&core);
}
