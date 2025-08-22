{{/*
Expand the name of the chart.
*/}}
{{- define "homenetmon.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "homenetmon.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "homenetmon.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "homenetmon.labels" -}}
helm.sh/chart: {{ include "homenetmon.chart" . }}
{{ include "homenetmon.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: homenetmon
{{- end }}

{{/*
Selector labels
*/}}
{{- define "homenetmon.selectorLabels" -}}
app.kubernetes.io/name: {{ include "homenetmon.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "homenetmon.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "homenetmon.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the name of the redis service
*/}}
{{- define "homenetmon.redis.fullname" -}}
{{- if .Values.redis.enabled }}
{{- printf "%s-redis-master" (include "homenetmon.fullname" .) }}
{{- else }}
{{- printf "%s-redis" (include "homenetmon.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Create the name of the postgresql service
*/}}
{{- define "homenetmon.postgresql.fullname" -}}
{{- if .Values.postgresql.enabled }}
{{- printf "%s-postgresql" (include "homenetmon.fullname" .) }}
{{- else }}
{{- printf "%s-postgresql" (include "homenetmon.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Create database URL
*/}}
{{- define "homenetmon.databaseUrl" -}}
{{- if .Values.postgresql.enabled }}
{{- printf "postgresql://%s:%s@%s:5432/%s" .Values.postgresql.auth.username .Values.postgresql.auth.password (include "homenetmon.postgresql.fullname" .) .Values.postgresql.auth.database }}
{{- else }}
{{- printf "sqlite:////app/data/homenetmon.db" }}
{{- end }}
{{- end }}

{{/*
Create Redis URL
*/}}
{{- define "homenetmon.redisUrl" -}}
{{- if .Values.redis.enabled }}
{{- if .Values.redis.auth.enabled }}
{{- printf "redis://:%s@%s:6379" .Values.redis.auth.password (include "homenetmon.redis.fullname" .) }}
{{- else }}
{{- printf "redis://%s:6379" (include "homenetmon.redis.fullname" .) }}
{{- end }}
{{- else }}
{{- printf "redis://homenetmon-redis:6379" }}
{{- end }}
{{- end }}

{{/*
Create image name
*/}}
{{- define "homenetmon.image" -}}
{{- if .Values.global.imageRegistry }}
{{- printf "%s/%s:%s" .Values.global.imageRegistry .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) }}
{{- else }}
{{- printf "%s/%s:%s" .Values.image.registry .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) }}
{{- end }}
{{- end }}

{{/*
Create nginx image name
*/}}
{{- define "homenetmon.nginx.image" -}}
{{- if .Values.global.imageRegistry }}
{{- printf "%s/%s:%s" .Values.global.imageRegistry .Values.nginx.image.repository .Values.nginx.image.tag }}
{{- else }}
{{- printf "%s/%s:%s" .Values.nginx.image.registry .Values.nginx.image.repository .Values.nginx.image.tag }}
{{- end }}
{{- end }}

{{/*
Generate secret key if not provided
*/}}
{{- define "homenetmon.secretKey" -}}
{{- if .Values.secrets.secretKey }}
{{- .Values.secrets.secretKey }}
{{- else }}
{{- randAlphaNum 64 }}
{{- end }}
{{- end }}

{{/*
Generate JWT secret key if not provided
*/}}
{{- define "homenetmon.jwtSecretKey" -}}
{{- if .Values.secrets.jwtSecretKey }}
{{- .Values.secrets.jwtSecretKey }}
{{- else }}
{{- randAlphaNum 64 }}
{{- end }}
{{- end }}

{{/*
Generate encryption key if not provided
*/}}
{{- define "homenetmon.encryptionKey" -}}
{{- if .Values.secrets.encryptionKey }}
{{- .Values.secrets.encryptionKey }}
{{- else }}
{{- randBytes 32 | b64enc }}
{{- end }}
{{- end }}

{{/*
Create storage class name
*/}}
{{- define "homenetmon.storageClassName" -}}
{{- if .Values.global.storageClass }}
{{- .Values.global.storageClass }}
{{- else if .Values.persistence.storageClass }}
{{- .Values.persistence.storageClass }}
{{- else }}
{{- "" }}
{{- end }}
{{- end }}

{{/*
Create log storage class name
*/}}
{{- define "homenetmon.logStorageClassName" -}}
{{- if .Values.global.storageClass }}
{{- .Values.global.storageClass }}
{{- else if .Values.logPersistence.storageClass }}
{{- .Values.logPersistence.storageClass }}
{{- else }}
{{- "" }}
{{- end }}
{{- end }}

{{/*
Common annotations
*/}}
{{- define "homenetmon.commonAnnotations" -}}
app.kubernetes.io/managed-by: helm
meta.helm.sh/release-name: {{ .Release.Name }}
meta.helm.sh/release-namespace: {{ .Release.Namespace }}
{{- end }}

{{/*
Pod annotations
*/}}
{{- define "homenetmon.podAnnotations" -}}
{{- if .Values.podAnnotations }}
{{- toYaml .Values.podAnnotations }}
{{- end }}
checksum/config: {{ include (print $.Template.BasePath "/configmap.yaml") . | sha256sum }}
checksum/secret: {{ include (print $.Template.BasePath "/secret.yaml") . | sha256sum }}
{{- end }}

{{/*
Image pull secrets
*/}}
{{- define "homenetmon.imagePullSecrets" -}}
{{- if .Values.global.imagePullSecrets }}
{{- range .Values.global.imagePullSecrets }}
- name: {{ . }}
{{- end }}
{{- else if .Values.image.pullSecrets }}
{{- range .Values.image.pullSecrets }}
- name: {{ . }}
{{- end }}
{{- end }}
{{- end }}