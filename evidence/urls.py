from django.urls import path
from .views import (
    EvidenceListCreateView,
    EvidenceRequestListCreateView,
    EvidenceRequestActionView,
    EvidenceReviewView,
    EvidenceIntegrityVerificationView,
)

urlpatterns = [
    path("", EvidenceListCreateView.as_view()),
    path("requests/", EvidenceRequestListCreateView.as_view()),
    path("requests/<int:pk>/action/", EvidenceRequestActionView.as_view()),
    path("<int:pk>/review/", EvidenceReviewView.as_view()),
    path("<int:pk>/verify-integrity/", EvidenceIntegrityVerificationView.as_view(), name="verify-integrity"),
]