import csv
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


IDENTITY_FIELDS = {"name", "email", "phone", "email_hash"}


def parse_timestamp(value: str) -> datetime:
    text = (value or "").strip()
    if not text:
        raise ValueError("Timestamp cannot be empty")

    parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))

    if parsed.tzinfo is None:
        raise ValueError(f"Timestamp must include a timezone: {value}")

    return parsed.astimezone(timezone.utc)


def normalize_value(field_name: str, value: str) -> str:
    """Normalize identifiers without changing their underlying meaning."""
    value = (value or "").strip()

    if field_name in {"email", "email_hash"}:
        return value.casefold()

    if field_name == "phone":
        digits = "".join(char for char in value if char.isdigit())
        return ("+" if value.startswith("+") else "") + digits

    if field_name == "name":
        return " ".join(value.casefold().split())

    return value.casefold()


@dataclass
class IdentityMatch:
    """Identity information supported by the supplied CSV records."""

    user_id: str
    requested_email: str
    audit_at: str
    matched_by: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    phones: list[str] = field(default_factory=list)
    email_hashes: list[str] = field(default_factory=list)
    names: list[str] = field(default_factory=list)
    audit_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "user_id": self.user_id,
            "requested_email": self.requested_email,
            "audit_at": self.audit_at,
            "matched_by": sorted(set(self.matched_by)),
            "emails": sorted(set(self.emails)),
            "phones": sorted(set(self.phones)),
            "email_hashes": sorted(set(self.email_hashes)),
            "names": sorted(set(self.names)),
            "audit_ids": sorted(set(self.audit_ids)),
        }


class IdentityResolver:
    def __init__(
        self,
        identities: list[dict[str, str]],
        audit_log: list[dict[str, str]],
    ):
        self.identities = identities
        self.audit_log = audit_log

        self._identities_by_user: dict[str, dict[str, str]] = {}
        for row in identities:
            user_id = (row.get("user_id") or "").strip()
            if not user_id:
                raise ValueError("Identity row has an empty user_id")
            if user_id in self._identities_by_user:
                raise ValueError(f"Duplicate identity row for {user_id}")
            self._identities_by_user[user_id] = row

        self._audit_by_user: dict[str, list[dict[str, str]]] = {}
        for row in audit_log:
            user_id = (row.get("user_id") or "").strip()
            if not user_id:
                continue
            self._audit_by_user.setdefault(user_id, []).append(row)

    @classmethod
    def from_dataset(cls, dataset_dir: str | Path) -> "IdentityResolver":
        """Load identity data from the two authoritative CSV files."""
        root = Path(dataset_dir)

        def read_csv(filename: str) -> list[dict[str, str]]:
            path = root / filename
            if not path.is_file():
                raise FileNotFoundError(f"Required identity file not found: {path}")

            with path.open("r", encoding="utf-8-sig", newline="") as handle:
                return list(csv.DictReader(handle))

        return cls(
            identities=read_csv("user_identities.csv"),
            audit_log=read_csv("user_audit_log.csv"),
        )

    def _email_candidates(
        self, audit_at: datetime
    ) -> dict[str, list[tuple[str, str]]]:
        candidates: dict[str, list[tuple[str, str]]] = {}

        def add(email: str, user_id: str, source: str) -> None:
            normalized = normalize_value("email", email)
            if not normalized:
                return
            candidates.setdefault(normalized, []).append((user_id, source))

        for user_id, row in self._identities_by_user.items():
            updated_at = (row.get("updated_at") or "").strip()
            if not updated_at:
                continue

            try:
                row_time = parse_timestamp(updated_at)
            except ValueError:
                continue

            if row_time <= audit_at:
                add(row.get("email", ""), user_id, "current_identity")

        for user_id, rows in self._audit_by_user.items():
            for row in rows:
                if (row.get("field_name") or "").strip().casefold() != "email":
                    continue

                event_time = (row.get("event_time") or "").strip()
                try:
                    if parse_timestamp(event_time) > audit_at:
                        continue
                except ValueError:
                    continue

                audit_id = (row.get("audit_id") or "").strip()
                source = f"historical_audit:{audit_id}" if audit_id else "historical_audit"

                add(row.get("old_value", ""), user_id, source)
                add(row.get("new_value", ""), user_id, source)

        return candidates

    def resolve(self, email: str, audit_at: str) -> list[IdentityMatch]:
        requested_email = (email or "").strip()
        if not requested_email:
            raise ValueError("Request email cannot be empty")

        cutoff = parse_timestamp(audit_at)
        target = normalize_value("email", requested_email)
        candidates = self._email_candidates(cutoff)

        matched = candidates.get(target, [])
        user_ids = sorted({user_id for user_id, _ in matched})

        results: list[IdentityMatch] = []

        for user_id in user_ids:
            match = IdentityMatch(
                user_id=user_id,
                requested_email=requested_email,
                audit_at=audit_at,
                matched_by=[
                    source for candidate_id, source in matched
                    if candidate_id == user_id
                ],
            )

            for row in self._audit_by_user.get(user_id, []):
                try:
                    if parse_timestamp(row.get("event_time", "")) > cutoff:
                        continue
                except ValueError:
                    continue

                field_name = (row.get("field_name") or "").strip().casefold()
                if field_name not in IDENTITY_FIELDS:
                    continue

                audit_id = (row.get("audit_id") or "").strip()
                if audit_id:
                    match.audit_ids.append(audit_id)

                old_value = (row.get("old_value") or "").strip()
                new_value = (row.get("new_value") or "").strip()

                if field_name == "email":
                    match.emails.extend([v for v in (old_value, new_value) if v])
                elif field_name == "phone":
                    match.phones.extend([v for v in (old_value, new_value) if v])
                elif field_name == "email_hash":
                    match.email_hashes.extend(
                        [v for v in (old_value, new_value) if v]
                    )
                elif field_name == "name":
                    match.names.extend([v for v in (old_value, new_value) if v])
            current = self._identities_by_user.get(user_id, {})
            try:
                current_is_available = (
                    parse_timestamp(current.get("updated_at", "")) <= cutoff
                )
            except ValueError:
                current_is_available = False

            if current_is_available:
                for field_name, target_list in (
                    ("email", match.emails),
                    ("phone", match.phones),
                    ("email_hash", match.email_hashes),
                    ("name", match.names),
                ):
                    value = (current.get(field_name) or "").strip()
                    if value:
                        target_list.append(value)

            results.append(match)

        return results


if __name__ == "__main__":
    import json

    resolver = IdentityResolver.from_dataset("dataset")
    test_cases = [
        ("amina.elmasri@gmail.com", "2026-09-03T11:30:00Z"),
        ("mateo.rios@outlook.com", "2026-09-04T15:00:00Z"),
    ]

    for email, audit_at in test_cases:
        matches = resolver.resolve(email, audit_at)
        print(json.dumps({
            "email": email,
            "audit_at": audit_at,
            "match_count": len(matches),
            "matches": [match.to_dict() for match in matches],
        }, ensure_ascii=False, indent=2))
