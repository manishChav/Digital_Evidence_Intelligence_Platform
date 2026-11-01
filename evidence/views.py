import hashlib
from django.db import transaction
from django.utils import timezone
from rest_framework import generics
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.exceptions import PermissionDenied, ValidationError, NotFound

from evidence.models import Evidence, EvidenceRequest
from evidence.serializers import EvidenceSerializer, EvidenceRequestSerializer
from evidence.services import validate_file, sha256_file, file_type
from accounts.models import User
from audit.services import audit
from custody.services import custody

from rest_framework import status

import logging

logger = logging.getLogger(__name__)

from evidence.models import AudioAnalysisResult
from evidence.audio_services import (
    calculate_file_sha256,
    transcribe_audio,
    analyze_audio_transcript,
)

class EvidenceListCreateView(generics.ListCreateAPIView):
    serializer_class = EvidenceSerializer
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]
    def get_queryset(self):
        u = self.request.user
        q = Evidence.objects.select_related("case")
        if u.role in [User.Role.ADMIN, User.Role.EVIDENCE_OFFICER]: return q
        if u.role == User.Role.INVESTIGATING_OFFICER: return q.filter(case__investigating_officer=u)
        if u.role == User.Role.FORENSIC_OFFICER: return q.filter(case__forensic_officer=u)
        if u.role == User.Role.SUPERVISOR: return q.filter(case__supervisor=u)
        return q.none()
    @transaction.atomic
    def perform_create(self, serializer):
        u = self.request.user
        if u.role not in [User.Role.ADMIN, User.Role.EVIDENCE_OFFICER, User.Role.INVESTIGATING_OFFICER]: raise PermissionDenied("Only Admin, Evidence, or Investigating Officers can upload evidence.")
        f = self.request.FILES.get("file")
        if not f: raise ValidationError({"file": "Upload a file using multipart form data."})
        validate_file(f)
        h = sha256_file(f)
        obj = serializer.save(
    case_id=self.request.data.get("case"),
    original_filename=f.name[:255],
    evidence_type=file_type(f.name),
    mime_type=getattr(f, "content_type", "") or "",
    file_size=f.size,
    sha256_hash=h,
    uploaded_by=u
)
        custody(obj, u, "UPLOADED", self.request, h)
        audit(u, "EVIDENCE_UPLOADED", {"evidence_id": obj.id, "case_id": obj.case_id, "sha256": h}, self.request)

class EvidenceRequestListCreateView(generics.ListCreateAPIView):
    serializer_class = EvidenceRequestSerializer
    permission_classes = [IsAuthenticated]
    def get_queryset(self):
        u = self.request.user
        if u.role == User.Role.ADMIN: return EvidenceRequest.objects.all()
        if u.role == User.Role.INVESTIGATING_OFFICER: return EvidenceRequest.objects.filter(requested_by=u)
        if u.role == User.Role.EVIDENCE_OFFICER: return EvidenceRequest.objects.filter(status="PENDING")
        return EvidenceRequest.objects.none()
    def perform_create(self, serializer):
        u = self.request.user
        if u.role != User.Role.INVESTIGATING_OFFICER: raise PermissionDenied("Only Investigating Officers can request evidence.")
        obj = serializer.save(requested_by=u)
        audit(u, "EVIDENCE_REQUESTED", {"request_id": obj.id}, self.request)

class EvidenceRequestActionView(APIView):
    permission_classes = [IsAuthenticated]
    def patch(self, request, pk):
        if request.user.role != User.Role.EVIDENCE_OFFICER: raise PermissionDenied("Evidence Officer only.")
        try: obj = EvidenceRequest.objects.get(pk=pk, status="PENDING")
        except EvidenceRequest.DoesNotExist: raise NotFound("Pending request not found.")
        action = request.data.get("action")
        if action not in ["FULFILLED", "REJECTED"]: raise ValidationError({"action": "Use FULFILLED or REJECTED."})
        obj.status = action
        obj.fulfilled_at = timezone.now() if action == "FULFILLED" else None
        obj.save()
        audit(request.user, "EVIDENCE_REQUEST_" + action, {"request_id": obj.id}, request)
        return Response(EvidenceRequestSerializer(obj).data)

class EvidenceReviewView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request, pk):
        u = request.user
        if u.role != User.Role.FORENSIC_OFFICER: raise PermissionDenied("Forensic Officer only.")
        try: obj = Evidence.objects.get(pk=pk, case__forensic_officer=u)
        except Evidence.DoesNotExist: raise NotFound("Evidence not found in your assigned cases.")
        obj.status = Evidence.Status.REVIEWED
        obj.forensic_reviewer = u
        obj.save(update_fields=["status", "forensic_reviewer"])
        custody(obj, u, "FORENSIC_REVIEWED", request, obj.sha256_hash)
        audit(u, "EVIDENCE_REVIEWED", {"evidence_id": obj.id}, request)
        return Response(EvidenceSerializer(obj).data)

class EvidenceIntegrityVerificationView(APIView):
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        u = self.request.user
        q = Evidence.objects.all()

        if u.role in [User.Role.ADMIN, User.Role.EVIDENCE_OFFICER]:
            return q
        if u.role == User.Role.INVESTIGATING_OFFICER:
            return q.filter(case__investigating_officer=u)
        if u.role == User.Role.FORENSIC_OFFICER:
            return q.filter(case__forensic_officer=u)
        if u.role == User.Role.SUPERVISOR:
            return q.filter(case__supervisor=u)

        return q.none()

    def post(self, request, pk):
        obj = self.get_queryset().filter(pk=pk).first()

        if obj is None:
            return Response(
                {"detail": "Evidence not found or access denied."},
                status=status.HTTP_404_NOT_FOUND,
            )

        try:
            obj.file.open("rb")
            try:
                h = hashlib.sha256()
                for chunk in obj.file.chunks():
                    h.update(chunk)
                calculated_hash = h.hexdigest()
            finally:
                obj.file.close()
        except (OSError, ValueError):
            audit(
                request.user,
                "EVIDENCE_INTEGRITY_VERIFICATION_FAILED",
                {"evidence_id": obj.id},
                request,
            )
            return Response(
                {"detail": "Evidence file is unavailable."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        verified = calculated_hash == obj.sha256_hash

        event = (
            "EVIDENCE_INTEGRITY_VERIFIED"
            if verified
            else "EVIDENCE_INTEGRITY_MISMATCH"
        )
        custody_event = "INTEGRITY_VERIFIED" if verified else "INTEGRITY_MISMATCH"

        audit(
            request.user,
            event,
            {
                "evidence_id": obj.id,
                "stored_sha256": obj.sha256_hash,
                "calculated_sha256": calculated_hash,
            },
            request,
        )
        custody(obj, request.user, custody_event, request, calculated_hash)

        return Response(
            {
                "evidence_id": obj.id,
                "integrity_verified": verified,
                "stored_sha256": obj.sha256_hash,
                "calculated_sha256": calculated_hash,
                "message": (
                    "Evidence integrity verified successfully."
                    if verified
                    else "Evidence integrity mismatch detected."
                ),
            },
            status=status.HTTP_200_OK,
        )

class AudioEvidenceAccessMixin:
    """Restrict audio operations to evidence the user may access."""

    def get_audio_evidence(self, request, pk):
        u = request.user
        queryset = Evidence.objects.select_related("case")

        if u.role in [User.Role.ADMIN, User.Role.EVIDENCE_OFFICER]:
            pass
        elif u.role == User.Role.INVESTIGATING_OFFICER:
            queryset = queryset.filter(case__investigating_officer=u)
        elif u.role == User.Role.FORENSIC_OFFICER:
            queryset = queryset.filter(case__forensic_officer=u)
        elif u.role == User.Role.SUPERVISOR:
            queryset = queryset.filter(case__supervisor=u)
        else:
            queryset = queryset.none()

        obj = queryset.filter(pk=pk).first()

        if obj is None:
            raise NotFound("Evidence not found or access denied.")

        if obj.evidence_type != Evidence.Type.AUDIO:
            raise ValidationError(
                {"evidence": "This operation is only available for audio evidence."}
            )

        return obj

    def verify_audio_integrity(self, obj, request):
        try:
            calculated_hash = calculate_file_sha256(obj.file.path)
        except (OSError, ValueError):
            audit(
                request.user,
                "AUDIO_INTEGRITY_CHECK_FAILED",
                {"evidence_id": obj.id},
                request,
            )
            raise ValidationError(
                {"file": "The audio evidence file is unavailable."}
            )

        verified = calculated_hash == obj.sha256_hash

        audit(
            request.user,
            "AUDIO_INTEGRITY_VERIFIED" if verified
            else "AUDIO_INTEGRITY_MISMATCH",
            {
                "evidence_id": obj.id,
                "stored_sha256": obj.sha256_hash,
                "calculated_sha256": calculated_hash,
            },
            request,
        )

        custody(
            obj,
            request.user,
            "AUDIO_INTEGRITY_VERIFIED" if verified
            else "AUDIO_INTEGRITY_MISMATCH",
            request,
            calculated_hash,
        )

        if not verified:
            raise ValidationError(
                {"integrity": "Audio evidence integrity verification failed."}
            )

        return calculated_hash


class AudioTranscriptionView(AudioEvidenceAccessMixin, APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        obj = self.get_audio_evidence(request, pk)
        self.verify_audio_integrity(obj, request)

        try:
            transcription = transcribe_audio(obj.file.path)
        except Exception:
            logger.exception(

            "Audio analysis failed for evidence ID %s",
            obj.id,
    )
        return Response(
        {"detail": "Audio analysis failed. Check server logs."},
        status=status.HTTP_500_INTERNAL_SERVER_ERROR,
    )

        audit(
            request.user,
            "AUDIO_TRANSCRIPTION_COMPLETED",
            {"evidence_id": obj.id},
            request,
        )

        return Response({
            "evidence_id": obj.id,
            "transcription": transcription,
        })


class AudioAnalysisView(AudioEvidenceAccessMixin, APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        obj = self.get_audio_evidence(request, pk)
        current_hash = self.verify_audio_integrity(obj, request)

        try:
            transcription = transcribe_audio(obj.file.path)
            analysis = analyze_audio_transcript(
                transcription["full_text"],
                obj.id,
            )
        except Exception:
            audit(
                request.user,
                "AUDIO_ANALYSIS_FAILED",
                {"evidence_id": obj.id},
                request,
            )
            return Response(
                {"detail": "Audio analysis failed. Check server logs."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        result, created = AudioAnalysisResult.objects.update_or_create(
            evidence=obj,
            defaults={
                "transcription": transcription,
                "analysis": analysis,
                "processed_hash": current_hash,
            },
        )

        obj.status = Evidence.Status.ANALYZED
        obj.save(update_fields=["status"])

        custody(
            obj,
            request.user,
            "AUDIO_ANALYSIS_COMPLETED",
            request,
            current_hash,
        )
        audit(
            request.user,
            "AUDIO_ANALYSIS_COMPLETED",
            {"evidence_id": obj.id, "result_id": result.id},
            request,
        )

        return Response({
            "evidence_id": obj.id,
            "transcription": result.transcription,
            "analysis": result.analysis,
            "processed_hash": result.processed_hash,
            "created": created,
        })


class AudioAnalysisResultView(AudioEvidenceAccessMixin, APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        obj = self.get_audio_evidence(request, pk)

        try:
            result = obj.audio_analysis
        except AudioAnalysisResult.DoesNotExist:
            raise NotFound("Audio analysis has not been generated yet.")

        return Response({
            "evidence_id": obj.id,
            "case_id": obj.case_id,
            "transcription": result.transcription,
            "analysis": result.analysis,
            "processed_hash": result.processed_hash,
            "created_at": result.created_at,
            "updated_at": result.updated_at,
        })    