{{/* Common labels and naming for the mcp-sse chart. */}}
{{- define "mcp-sse.fullname" -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "mcp-sse.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{ include "mcp-sse.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end -}}

{{- define "mcp-sse.selectorLabels" -}}
app.kubernetes.io/name: mcp-sse
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* Effective Secret name — either the operator-provisioned one or
     the chart-managed sibling. Used by Deployment volumes + envFrom. */}}
{{- define "mcp-sse.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{ .Values.secrets.existingSecret }}
{{- else -}}
{{ include "mcp-sse.fullname" . }}-secrets
{{- end -}}
{{- end -}}
