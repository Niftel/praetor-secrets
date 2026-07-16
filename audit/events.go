package audit

const (
	EventTypeRequestCompleted = "request_completed"
	EventTypeStateTransition  = "state_transition"

	ResultSuccess  = "success"
	ResultDenied   = "denied"
	ResultRejected = "rejected"
	ResultError    = "error"

	ReasonCompleted             = "completed"
	ReasonOperationNotPermitted = "operation_not_permitted"
	ReasonInvalidRequest        = "invalid_request"
	ReasonSecureOperationFailed = "secure_operation_failed"

	OperationUnknownRoute               = "unknown_route"
	OperationSecurityStatusRead         = "security_status_read"
	OperationCredentialCreated          = "credential_created"
	OperationCredentialRead             = "credential_read"
	OperationCredentialInputsReplaced   = "credential_inputs_replaced"
	OperationCredentialMetadataUpdated  = "credential_metadata_updated"
	OperationCredentialRetired          = "credential_retired"
	OperationRunBindingRegistered       = "run_binding_registered"
	OperationRunBindingInspected        = "run_binding_inspected"
	OperationRunBindingCanceled         = "run_binding_canceled"
	OperationRunBindingExpired          = "run_binding_expired"
	OperationRunBindingExhausted        = "run_binding_exhausted"
	OperationCredentialResolved         = "credential_resolved"
	OperationMasterKeyRotationStarted   = "master_key_rotation_started"
	OperationMasterKeyRotationResumed   = "master_key_rotation_resumed"
	OperationCredentialKeyRotated       = "credential_key_rotated"
	OperationMasterKeyRotationFinalized = "master_key_rotation_finalized"
	OperationRecoveryValidationStarted  = "recovery_validation_started"
	OperationRecoveryValidationFinished = "recovery_validation_finished"
)

var knownEventTypes = map[string]struct{}{
	EventTypeRequestCompleted: {},
	EventTypeStateTransition:  {},
}

var knownResults = map[string]struct{}{
	ResultSuccess:  {},
	ResultDenied:   {},
	ResultRejected: {},
	ResultError:    {},
}

var knownOperations = map[string]struct{}{
	OperationUnknownRoute:               {},
	OperationSecurityStatusRead:         {},
	OperationCredentialCreated:          {},
	OperationCredentialRead:             {},
	OperationCredentialInputsReplaced:   {},
	OperationCredentialMetadataUpdated:  {},
	OperationCredentialRetired:          {},
	OperationRunBindingRegistered:       {},
	OperationRunBindingInspected:        {},
	OperationRunBindingCanceled:         {},
	OperationRunBindingExpired:          {},
	OperationRunBindingExhausted:        {},
	OperationCredentialResolved:         {},
	OperationMasterKeyRotationStarted:   {},
	OperationMasterKeyRotationResumed:   {},
	OperationCredentialKeyRotated:       {},
	OperationMasterKeyRotationFinalized: {},
	OperationRecoveryValidationStarted:  {},
	OperationRecoveryValidationFinished: {},
}

func KnownOperation(operation string) bool {
	_, ok := knownOperations[operation]
	return ok
}
