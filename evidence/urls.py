from django.urls import path
from .views import (
    EvidenceListCreateView,
    EvidenceRequestListCreateView,
    EvidenceRequestActionView,
    EvidenceReviewView,
    EvidenceIntegrityVerificationView,
    AudioTranscriptionView,
    AudioAnalysisView,
    AudioAnalysisResultView,
)

urlpatterns = [
    path("", EvidenceListCreateView.as_view()),
    path("requests/", EvidenceRequestListCreateView.as_view()),
    path("requests/<int:pk>/action/", EvidenceRequestActionView.as_view()),
    path("<int:pk>/review/", EvidenceReviewView.as_view()),
    path("<int:pk>/verify-integrity/", EvidenceIntegrityVerificationView.as_view(), name="verify-integrity"),
    path("<int:pk>/transcribe-audio/", AudioTranscriptionView.as_view()),
    path("<int:pk>/analyze-audio/", AudioAnalysisView.as_view()),
    path("<int:pk>/audio-analysis/", AudioAnalysisResultView.as_view()),
]