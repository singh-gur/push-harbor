{{- define "pushharbor.labels" -}}
app.kubernetes.io/name: pushharbor
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "pushharbor.selector" -}}
app.kubernetes.io/name: pushharbor
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
