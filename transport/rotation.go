package transport

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/Niftel/praetor-secrets/credential"
)

type resumeRotationBody struct {
	BatchSize int `json:"batch_size"`
}

type rotateCredentialBody struct {
	OrganizationID string `json:"organization_id"`
}
type recoveryValidationBody struct {
	SampleSize int `json:"sample_size"`
}

func (server *Server) operationRoute(writer http.ResponseWriter, request *http.Request, identity credential.WorkloadIdentity, path string) {
	if identity.Role != credential.RoleSecretsOperator {
		writeProblem(writer, http.StatusForbidden, "operation_not_permitted")
		return
	}
	switch {
	case request.Method == http.MethodPost && path == "/internal/v1/operations/recovery-validations":
		var body recoveryValidationBody
		if err := decodeJSON(request, &body); err != nil {
			writeDecodeProblem(writer, err)
			return
		}
		result, err := server.service.ValidateRecovery(request.Context(), body.SampleSize)
		if err != nil {
			writeServiceProblem(writer, err)
			return
		}
		writeJSON(writer, http.StatusOK, result)
	case request.Method == http.MethodPost && path == "/internal/v1/operations/backups":
		var body credential.BackupSet
		if err := decodeJSON(request, &body); err != nil {
			writeDecodeProblem(writer, err)
			return
		}
		result, err := server.service.RegisterBackup(request.Context(), body)
		if err != nil {
			writeServiceProblem(writer, err)
			return
		}
		writeJSON(writer, http.StatusCreated, result)
	case request.Method == http.MethodPost && strings.HasPrefix(path, "/internal/v1/operations/backups/") && strings.HasSuffix(path, "/expire"):
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/internal/v1/operations/backups/"), "/expire")
		if id == "" || strings.Contains(id, "/") {
			writeProblem(writer, http.StatusNotFound, "resource_not_found")
			return
		}
		result, err := server.service.ExpireBackup(request.Context(), id)
		if err != nil {
			writeServiceProblem(writer, err)
			return
		}
		writeJSON(writer, http.StatusOK, result)
	case request.Method == http.MethodGet && path == "/internal/v1/operations/key-status":
		status, err := server.service.KeyStatus(request.Context())
		if err != nil {
			writeServiceProblem(writer, err)
			return
		}
		writeJSON(writer, http.StatusOK, status)
	case request.Method == http.MethodPost && path == "/internal/v1/operations/rotations":
		rotation, err := server.service.StartMasterKeyRotation(request.Context())
		if err != nil {
			writeServiceProblem(writer, err)
			return
		}
		writer.Header().Set("Location", "/internal/v1/operations/rotations/"+rotation.ID)
		writeJSON(writer, http.StatusCreated, rotation)
	case strings.HasPrefix(path, "/internal/v1/operations/rotations/"):
		server.rotationRoute(writer, request, path)
	case request.Method == http.MethodPost && strings.HasPrefix(path, "/internal/v1/operations/credentials/") && strings.HasSuffix(path, "/rotate"):
		server.rotateCredential(writer, request, path)
	default:
		writeProblem(writer, http.StatusNotFound, "resource_not_found")
	}
}

func (server *Server) rotationRoute(writer http.ResponseWriter, request *http.Request, path string) {
	remainder := strings.TrimPrefix(path, "/internal/v1/operations/rotations/")
	parts := strings.Split(remainder, "/")
	if len(parts) == 0 || parts[0] == "" {
		writeProblem(writer, http.StatusNotFound, "resource_not_found")
		return
	}
	rotationID := parts[0]
	switch {
	case request.Method == http.MethodGet && len(parts) == 1:
		rotation, err := server.service.GetMasterKeyRotation(request.Context(), rotationID)
		if err != nil {
			writeServiceProblem(writer, err)
			return
		}
		writeJSON(writer, http.StatusOK, rotation)
	case request.Method == http.MethodPost && len(parts) == 2 && parts[1] == "resume":
		var body resumeRotationBody
		if err := decodeJSON(request, &body); err != nil {
			writeDecodeProblem(writer, err)
			return
		}
		if body.BatchSize < 1 || body.BatchSize > 1000 {
			writeProblem(writer, http.StatusBadRequest, "invalid_request")
			return
		}
		rotation, err := server.service.ResumeMasterKeyRotation(request.Context(), rotationID, body.BatchSize)
		if err != nil {
			writeServiceProblem(writer, err)
			return
		}
		writeJSON(writer, http.StatusOK, rotation)
	case request.Method == http.MethodPost && len(parts) == 2 && parts[1] == "finalize":
		rotation, err := server.service.FinalizeMasterKeyRotation(request.Context(), rotationID)
		if err != nil {
			writeServiceProblem(writer, err)
			return
		}
		writeJSON(writer, http.StatusOK, rotation)
	default:
		writeProblem(writer, http.StatusNotFound, "resource_not_found")
	}
}

func (server *Server) rotateCredential(writer http.ResponseWriter, request *http.Request, path string) {
	remainder := strings.TrimSuffix(strings.TrimPrefix(path, "/internal/v1/operations/credentials/"), "/rotate")
	parts := strings.Split(strings.Trim(remainder, "/"), "/")
	if len(parts) != 3 || parts[1] != "versions" {
		writeProblem(writer, http.StatusNotFound, "resource_not_found")
		return
	}
	version, err := strconv.ParseUint(parts[2], 10, 64)
	if err != nil || version == 0 {
		writeProblem(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	var body rotateCredentialBody
	if err := decodeJSON(request, &body); err != nil {
		writeDecodeProblem(writer, err)
		return
	}
	if err := server.service.RotateCredentialKey(request.Context(), credential.CredentialRotationRequest{
		OrganizationID: body.OrganizationID, CredentialID: parts[0], Version: version,
	}); err != nil {
		writeServiceProblem(writer, err)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func requestRotationID(path string) string {
	if !strings.HasPrefix(path, "/internal/v1/operations/rotations/") {
		return ""
	}
	value := strings.TrimPrefix(path, "/internal/v1/operations/rotations/")
	value = strings.TrimSuffix(value, "/resume")
	value = strings.TrimSuffix(value, "/finalize")
	if strings.Contains(value, "/") || len(value) != 36 {
		return ""
	}
	return value
}
