from django.db import models
from django.conf import settings
from investigations.models import InvestigationCase

class Evidence(models.Model):
    class Type(models.TextChoices):
        IMAGE = "IMAGE", "Image"
        VIDEO = "VIDEO", "Video"
        AUDIO = "AUDIO", "Audio"
        DOCUMENT = "DOCUMENT", "Document"
        OTHER = "OTHER", "Other"
    class Status(models.TextChoices):
        UPLOADED = "UPLOADED", "Uploaded"
        PROCESSING = "PROCESSING", "Processing"
        ANALYZED = "ANALYZED", "Analyzed"
        REVIEWED = "REVIEWED", "Reviewed"
    case = models.ForeignKey(InvestigationCase, on_delete=models.PROTECT, related_name="evidence")
    file = models.FileField(upload_to="evidence/%Y/%m/%d/")
    original_filename = models.CharField(max_length=255)
    evidence_type = models.CharField(max_length=20, choices=Type.choices)
    mime_type = models.CharField(max_length=100, blank=True)
    file_size = models.PositiveBigIntegerField(default=0)
    sha256_hash = models.CharField(max_length=64, db_index=True)
    uploaded_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="evidence_uploaded")
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.UPLOADED)
    forensic_reviewer = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="evidence_reviewed", null=True, blank=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    def __str__(self): return self.original_filename

class EvidenceRequest(models.Model):
    class Status(models.TextChoices):
        PENDING = "PENDING", "Pending"
        FULFILLED = "FULFILLED", "Fulfilled"
        REJECTED = "REJECTED", "Rejected"
    case = models.ForeignKey(InvestigationCase, on_delete=models.PROTECT, related_name="evidence_requests")
    requested_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    description = models.TextField()
    requested_type = models.CharField(max_length=20, choices=Evidence.Type.choices)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
    created_at = models.DateTimeField(auto_now_add=True)
    fulfilled_at = models.DateTimeField(null=True, blank=True)


class AudioAnalysisResult(models.Model):
    evidence = models.OneToOneField(
        Evidence,
        on_delete=models.CASCADE,
        related_name="audio_analysis",
    )
    transcription = models.JSONField()
    analysis = models.JSONField()
    processed_hash = models.CharField(max_length=64)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Audio Analysis for Evidence {self.evidence_id}"