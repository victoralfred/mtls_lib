package mtls

/*
#include <mtls/mtls_hsm.h>
*/
import "C"

import (
	"runtime"
	"sync"
)

// HSMContext wraps an mTLS HSM context for hardware-backed key operations.
//
// HSMContext is safe for concurrent use after initialization.
type HSMContext struct {
	h  *C.mtls_hsm_ctx
	mu sync.Mutex

	// pinCallbackID is the registry ID for the Go PIN callback, if set.
	pinCallbackID uintptr
}

// HSMKeyInfo holds information about a key stored in the HSM.
type HSMKeyInfo struct {
	ID             string
	Label          string
	KeyType        uint32
	KeySize        uint32
	IsPrivate      bool
	Extractable    bool
	SignCapable     bool
	DecryptCapable  bool
}

// HSMSlotInfo holds information about an HSM slot.
type HSMSlotInfo struct {
	SlotID       uint64
	Description  string
	Manufacturer string
	TokenPresent bool
	LoginRequired bool
	TokenLabel   string
	TokenSerial  string
}

// NewHSMContext initializes an HSM context from the given configuration.
//
// HSMConfig fields map to mtls_hsm_config. The HSMType field in Config
// controls whether PKCS#11 or ENGINE interface is used.
func NewHSMContext(cfg *Config) (*HSMContext, error) {
	if cfg == nil {
		return nil, &Error{Code: ErrInvalidArgument, Message: "config is nil"}
	}

	var cCfg C.mtls_hsm_config
	C.mtls_hsm_config_init(&cCfg)

	cCfg._type = C.mtls_hsm_type(cfg.HSMType)

	// All C strings are stack/defer freed; valid for duration of mtls_hsm_init.
	var modulePath, slotID, tokenLabel, keyID, keyLabel, pin, engineID *C.char

	if cfg.HSMModulePath != "" {
		modulePath = C.CString(cfg.HSMModulePath)
		defer freeString(modulePath)
		cCfg.module_path = modulePath
	}
	if cfg.HSMSlotID != "" {
		slotID = C.CString(cfg.HSMSlotID)
		defer freeString(slotID)
		cCfg.slot_id = slotID
	}
	if cfg.HSMTokenLabel != "" {
		tokenLabel = C.CString(cfg.HSMTokenLabel)
		defer freeString(tokenLabel)
		cCfg.token_label = tokenLabel
	}
	if cfg.HSMKeyID != "" {
		keyID = C.CString(cfg.HSMKeyID)
		defer freeString(keyID)
		cCfg.key_id = keyID
	}
	if cfg.HSMKeyLabel != "" {
		keyLabel = C.CString(cfg.HSMKeyLabel)
		defer freeString(keyLabel)
		cCfg.key_label = keyLabel
	}
	if cfg.HSMPIN != "" {
		pin = C.CString(cfg.HSMPIN)
		defer freeString(pin)
		cCfg.pin = pin
	}
	if cfg.HSMEngineID != "" {
		engineID = C.CString(cfg.HSMEngineID)
		defer freeString(engineID)
		cCfg.engine_id = engineID
	}

	var cErr C.mtls_err
	initErr(&cErr)

	var h *C.mtls_hsm_ctx
	if C.mtls_hsm_init(&h, &cCfg, &cErr) != 0 {
		return nil, convertError(&cErr)
	}

	ctx := &HSMContext{h: h}
	runtime.SetFinalizer(ctx, (*HSMContext).destroy)
	return ctx, nil
}

// Close logs out and frees all HSM resources.
func (h *HSMContext) Close() {
	h.destroy()
}

func (h *HSMContext) destroy() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.h != nil {
		if h.pinCallbackID != 0 {
			unregisterCallback(h.pinCallbackID)
			h.pinCallbackID = 0
		}
		C.mtls_hsm_free(h.h)
		h.h = nil
		runtime.SetFinalizer(h, nil)
	}
}

// ListSlots returns information about available HSM slots.
func (h *HSMContext) ListSlots() ([]HSMSlotInfo, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.h == nil {
		return nil, &Error{Code: ErrCtxNotInitialized, Message: "HSM context is closed"}
	}

	const maxSlots = 32
	var slots [maxSlots]C.mtls_hsm_slot_info
	var slotCount C.size_t
	var cErr C.mtls_err
	initErr(&cErr)

	if C.mtls_hsm_list_slots(h.h, &slots[0], C.size_t(maxSlots), &slotCount, &cErr) != 0 {
		return nil, convertError(&cErr)
	}

	result := make([]HSMSlotInfo, int(slotCount))
	for i := range result {
		s := &slots[i]
		result[i] = HSMSlotInfo{
			SlotID:        uint64(s.slot_id),
			Description:   C.GoString(&s.description[0]),
			Manufacturer:  C.GoString(&s.manufacturer[0]),
			TokenPresent:  bool(s.token_present),
			LoginRequired: bool(s.login_required),
			TokenLabel:    C.GoString(&s.token_label[0]),
			TokenSerial:   C.GoString(&s.token_serial[0]),
		}
	}
	return result, nil
}

// ListKeys returns information about keys in the current slot.
// The HSM context must be logged in.
func (h *HSMContext) ListKeys() ([]HSMKeyInfo, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.h == nil {
		return nil, &Error{Code: ErrCtxNotInitialized, Message: "HSM context is closed"}
	}

	const maxKeys = 64
	var keys [maxKeys]C.mtls_hsm_key_info
	var keyCount C.size_t
	var cErr C.mtls_err
	initErr(&cErr)

	if C.mtls_hsm_list_keys(h.h, &keys[0], C.size_t(maxKeys), &keyCount, &cErr) != 0 {
		return nil, convertError(&cErr)
	}

	result := make([]HSMKeyInfo, int(keyCount))
	for i := range result {
		k := &keys[i]
		result[i] = HSMKeyInfo{
			ID:            C.GoString(&k.id[0]),
			Label:         C.GoString(&k.label[0]),
			KeyType:       uint32(k.key_type),
			KeySize:       uint32(k.key_size),
			IsPrivate:     bool(k.is_private),
			Extractable:   bool(k.extractable),
			SignCapable:    bool(k.sign_capable),
			DecryptCapable: bool(k.decrypt_capable),
		}
	}
	return result, nil
}

// GetInfo returns the HSM module description and version string.
func (h *HSMContext) GetInfo() (description, version string, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.h == nil {
		return "", "", &Error{Code: ErrCtxNotInitialized, Message: "HSM context is closed"}
	}

	var descBuf [256]C.char
	var verBuf [32]C.char
	var cErr C.mtls_err
	initErr(&cErr)

	if C.mtls_hsm_get_info(h.h, &descBuf[0], &verBuf[0], &cErr) != 0 {
		return "", "", convertError(&cErr)
	}
	return C.GoString(&descBuf[0]), C.GoString(&verBuf[0]), nil
}
