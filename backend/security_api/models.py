from django.db import models


class IPBlockDecision(models.Model):
    """
    Persistent administrator decision for an IP address.

    This records whether an administrator has explicitly chosen
    to keep an IP unblocked or has approved a future block.
    """

    DECISION_PENDING = "pending"
    DECISION_UNBLOCKED = "unblocked"
    DECISION_APPROVED = "approved"
    DECISION_DENIED = "denied"

    DECISION_CHOICES = [
        (DECISION_PENDING, "Pending"),
        (DECISION_UNBLOCKED, "Unblocked"),
        (DECISION_APPROVED, "Approved"),
        (DECISION_DENIED, "Denied"),
    ]

    ip_address = models.GenericIPAddressField(
        protocol="IPv4",
        unique=True,
    )

    decision = models.CharField(
        max_length=20,
        choices=DECISION_CHOICES,
    )

    source = models.CharField(
        max_length=32,
        default="FIREWALL",
    )

    reason = models.TextField(
        blank=True,
        default="",
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
    )

    updated_at = models.DateTimeField(
        auto_now=True,
    )

    class Meta:
        ordering = ["-updated_at"]

    def __str__(self):
        return f"{self.ip_address} - {self.decision}"
