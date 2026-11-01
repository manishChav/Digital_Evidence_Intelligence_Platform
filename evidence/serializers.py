from rest_framework import serializers
from evidence.models import Evidence, EvidenceRequest


class EvidenceSerializer(serializers.ModelSerializer):
    uploaded_by = serializers.PrimaryKeyRelatedField(read_only=True)
    forensic_reviewer = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = Evidence
        fields = [
            "id",
            "case",
            "file",
            "original_filename",
            "evidence_type",
            "mime_type",
            "file_size",
            "sha256_hash",
            "uploaded_by",
            "status",
            "forensic_reviewer",
            "uploaded_at",
        ]

        read_only_fields = [
            "id",
            "original_filename",
            "evidence_type",
            "mime_type",
            "file_size",
            "sha256_hash",
            "uploaded_by",
            "status",
            "forensic_reviewer",
            "uploaded_at",
        ]


class EvidenceRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = EvidenceRequest
        fields = "__all__"
        read_only_fields = [
            "id",
            "requested_by",
            "status",
            "created_at",
            "fulfilled_at",
        ]