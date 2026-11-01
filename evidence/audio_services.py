import hashlib
import json

import requests
from faster_whisper import WhisperModel


def calculate_file_sha256(file_path):
    """Calculate the SHA-256 hash of a stored evidence file."""
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


def transcribe_audio(audio_path):
    """Transcribe audio using Faster-Whisper."""
    model = WhisperModel(
        "base",
        device="cpu",
        compute_type="int8",
    )

    segments, info = model.transcribe(audio_path, beam_size=5)

    transcript_segments = []

    for segment in segments:
        transcript_segments.append({
            "start": round(segment.start, 2),
            "end": round(segment.end, 2),
            "text": segment.text.strip(),
        })

    full_text = " ".join(
        segment["text"] for segment in transcript_segments
    )

    return {
        "language": info.language,
        "language_probability": round(info.language_probability, 3),
        "segments": transcript_segments,
        "full_text": full_text,
    }


def analyze_audio_transcript(transcript, evidence_id):
    """Analyze a transcript using a local Ollama model."""

    url = "http://localhost:11434/api/chat"

    prompt = f"""
Analyze this audio transcript for a digital forensics investigation.

Evidence ID: {evidence_id}

Transcript:
{transcript}

Return a JSON object with these fields:
{{
    "summary": "Brief summary of the conversation",
    "people_mentioned": [],
    "dates_and_times": [],
    "locations_mentioned": [],
    "key_statements": [],
    "uncertainties": [],
    "requires_human_review": true
}}

Rules:
- Use only information supported by the transcript.
- Do not invent facts or identities.
- Use empty lists when information is unavailable.
- Keep the summary concise.
- This is preliminary investigative assistance, not proof of wrongdoing.
"""

    payload = {
        "model": "qwen3:4b",
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a concise digital forensics assistant. "
                    "Return only the requested JSON object. "
                    "Do not include explanations outside the JSON."
                ),
            },
            {"role": "user", "content": prompt},
        ],
        "stream": False,
        "think": False,
        "format": "json",
        "options": {
            "num_predict": 400,
            "temperature": 0,
        },
    }

    try:
        response = requests.post(
            url,
            json=payload,
            timeout=600,
        )
        response.raise_for_status()

        result = response.json()
        content = result.get("message", {}).get("content", "")

        if not content.strip():
            raise RuntimeError("Ollama returned empty analysis content.")

        try:
            return json.loads(content)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                "Ollama returned invalid JSON."
            ) from exc

    except requests.exceptions.Timeout as exc:
        raise RuntimeError(
            "Ollama timed out while analyzing the transcript."
        ) from exc

    except requests.exceptions.HTTPError as exc:
        raise RuntimeError(
            f"Ollama returned an HTTP error: {exc}"
        ) from exc

    except requests.exceptions.RequestException as exc:
        raise RuntimeError(
            f"Could not connect to Ollama: {exc}"
        ) from exc