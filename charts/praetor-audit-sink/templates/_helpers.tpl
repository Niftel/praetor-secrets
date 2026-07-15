{{- define "praetor-audit-sink.name" -}}{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}{{- end -}}
{{- define "praetor-audit-sink.fullname" -}}{{- if .Values.fullnameOverride -}}{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}{{- else -}}{{- printf "%s-%s" .Release.Name (include "praetor-audit-sink.name" .) | trunc 63 | trimSuffix "-" -}}{{- end -}}{{- end -}}
{{- define "praetor-audit-sink.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "praetor-audit-sink.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
{{- define "praetor-audit-sink.selectorLabels" -}}
app.kubernetes.io/name: {{ include "praetor-audit-sink.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- define "praetor-audit-sink.serviceAccountName" -}}{{- if .Values.serviceAccount.create -}}{{- default (include "praetor-audit-sink.fullname" .) .Values.serviceAccount.name -}}{{- else -}}{{- required "serviceAccount.name is required when serviceAccount.create=false" .Values.serviceAccount.name -}}{{- end -}}{{- end -}}
