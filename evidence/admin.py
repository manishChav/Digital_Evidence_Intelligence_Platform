from django.contrib import admin
from .models import Evidence, EvidenceRequest, AudioAnalysisResult

admin.site.register(Evidence)
admin.site.register(EvidenceRequest)
admin.site.register(AudioAnalysisResult)