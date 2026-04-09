"""
Database Models for CIT Document Tracker

Models:
  - UserProfile: Extends Django's User with roles (Admin, Staff, Viewer)
  - Document: Stores document metadata with IDEA-encrypted sensitive fields
  - DocumentLog: Audit trail for all document actions
  - QRCode: Stores QR code image references per document
"""

import secrets
from django.db import models
from django.contrib.auth.models import User


class UserProfile(models.Model):
    """
    Extends the built-in Django User model with a role field.
    
    Roles and their permissions:
      ADMIN  — Full access: create, read, update, delete, generate QR
      STAFF  — Can create, read, update documents and generate QR
      VIEWER — Read-only access to documents
    """
    ROLE_CHOICES = [
        ('admin',  'Administrator'),
        ('staff',  'Staff'),
        ('viewer', 'Viewer'),
    ]
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='viewer')
    
    def __str__(self):
        return f"{self.user.username} ({self.role})"


class Document(models.Model):
    """
    Core document model.
    
    Sensitive fields (title, description, notes) are stored IDEA-encrypted
    in the database. They are encrypted on save and decrypted on read
    via the serializer.
    
    STATUS FLOW:
      Pending → In Review → Approved → Archived
               ↘ Rejected
    """
    STATUS_CHOICES = [
        ('pending',    'Pending'),
        ('in_review',  'In Review'),
        ('approved',   'Approved'),
        ('rejected',   'Rejected'),
        ('archived',   'Archived'),
    ]
    
    CATEGORY_CHOICES = [
        ('memo',       'Memorandum'),
        ('report',     'Report'),
        ('request',    'Request'),
        ('certificate','Certificate'),
        ('letter',     'Letter'),
        ('form',       'Form'),
        ('other',      'Other'),
    ]
    
    # Metadata fields
    document_code   = models.CharField(max_length=50, unique=True)      # e.g., CIT-2024-001
    title           = models.TextField()                                  # IDEA-encrypted
    category        = models.CharField(max_length=20, choices=CATEGORY_CHOICES, default='other')
    status          = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    description     = models.TextField(blank=True, null=True)            # IDEA-encrypted
    notes           = models.TextField(blank=True, null=True)            # IDEA-encrypted
    
    # Tracking fields
    created_by      = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_docs')
    assigned_to     = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='assigned_docs')
    created_at      = models.DateTimeField(auto_now_add=True)
    updated_at      = models.DateTimeField(auto_now=True)
    due_date        = models.DateField(null=True, blank=True)
    location        = models.TextField(blank=True, null=True)        # IDEA-encrypted
    document_key    = models.CharField(max_length=64, unique=True, blank=True)
    
    # Encryption flag — marks whether fields are IDEA-encrypted
    is_encrypted    = models.BooleanField(default=True)
    
    class Meta:
        ordering = ['-created_at']

    def save(self, *args, **kwargs):
        if not self.document_key:
            self.document_key = secrets.token_urlsafe(24)
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"{self.document_code}"


class DocumentAttachment(models.Model):
    """
    Encrypted file attachment for a document.
    """
    document = models.ForeignKey(Document, on_delete=models.CASCADE, related_name='attachments')
    file = models.FileField(upload_to='attachments/')
    original_name = models.CharField(max_length=255)
    uploaded_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    is_encrypted = models.BooleanField(default=True)

    class Meta:
        ordering = ['-uploaded_at']

    def __str__(self):
        return f"{self.original_name} ({self.document.document_code})"


class DocumentLog(models.Model):
    """
    Immutable audit trail for every action performed on a document.
    Logs are created automatically when documents are created, updated,
    or change status.
    """
    ACTION_CHOICES = [
        ('created',       'Created'),
        ('updated',       'Updated'),
        ('status_change', 'Status Changed'),
        ('viewed',        'Viewed'),
        ('qr_generated',  'QR Code Generated'),
        ('deleted',       'Deleted'),
    ]
    
    document    = models.ForeignKey(Document, on_delete=models.CASCADE, related_name='logs')
    action      = models.CharField(max_length=20, choices=ACTION_CHOICES)
    performed_by= models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    details     = models.TextField(blank=True)   # IDEA-encrypted description
    timestamp   = models.DateTimeField(auto_now_add=True)
    is_encrypted= models.BooleanField(default=True)
    
    class Meta:
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"{self.document} - {self.action} by {self.performed_by}"


class QRCode(models.Model):
    """
    QR Code record linked to a Document.
    Stores the generated QR image file and the URL it encodes.
    """
    document    = models.OneToOneField(Document, on_delete=models.CASCADE, related_name='qr_code')
    image       = models.ImageField(upload_to='qrcodes/')
    encoded_url = models.URLField()   # The URL embedded in the QR code
    generated_at= models.DateTimeField(auto_now_add=True)
    generated_by= models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    
    def __str__(self):
        return f"QR for {self.document.document_code}"