"""
DRF Serializers for CIT Document Tracker

Handles IDEA encryption/decryption transparently:
  - On create/update: encrypts sensitive fields before saving to DB
  - On read: decrypts sensitive fields before sending to frontend
"""

from rest_framework import serializers
from django.contrib.auth.models import User
from .models import UserProfile, Document, DocumentLog, QRCode, DocumentAttachment
from .idea_encryption import encrypt_document_field, decrypt_document_field


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ['role']


class UserSerializer(serializers.ModelSerializer):
    """Serializes user data including their role from UserProfile."""
    role = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = ['id', 'username', 'first_name', 'last_name', 'email', 'role']
    
    def get_role(self, obj):
        # Get role from related UserProfile
        try:
            return obj.profile.role
        except UserProfile.DoesNotExist:
            return 'viewer'


class RegisterSerializer(serializers.ModelSerializer):
    """Handles new user registration with password + role."""
    password = serializers.CharField(write_only=True, min_length=6)
    role     = serializers.ChoiceField(choices=['admin', 'staff', 'viewer'])
    
    class Meta:
        model = User
        fields = ['username', 'password', 'first_name', 'last_name', 'email', 'role']
    
    def create(self, validated_data):
        role = validated_data.pop('role')
        user = User.objects.create_user(**validated_data)
        # Create the associated UserProfile with the selected role
        UserProfile.objects.create(user=user, role=role)
        return user


class DocumentLogSerializer(serializers.ModelSerializer):
    performed_by = UserSerializer(read_only=True)
    
    class Meta:
        model = DocumentLog
        fields = ['id', 'action', 'performed_by', 'details', 'timestamp', 'is_encrypted']
    
    def to_representation(self, instance):
        """Decrypt details if they are encrypted."""
        data = super().to_representation(instance)
        if instance.is_encrypted and instance.details:
            try:
                data['details'] = decrypt_document_field(instance.details)
            except Exception:
                data['details'] = ''
        return data


class QRCodeSerializer(serializers.ModelSerializer):
    class Meta:
        model = QRCode
        fields = ['id', 'image', 'encoded_url', 'generated_at', 'generated_by']


class DocumentAttachmentSerializer(serializers.ModelSerializer):
    uploaded_by = UserSerializer(read_only=True)
    download_url = serializers.SerializerMethodField()

    class Meta:
        model = DocumentAttachment
        fields = ['id', 'original_name', 'uploaded_by', 'uploaded_at', 'is_encrypted', 'download_url']

    def get_download_url(self, obj):
        request = self.context.get('request') if self.context else None
        if not request:
            return None
        return request.build_absolute_uri(
            f"/api/documents/{obj.document.id}/attachments/{obj.id}/download/"
        )


class DocumentSerializer(serializers.ModelSerializer):
    """
    Document serializer with IDEA encryption/decryption.
    
    READ:  Encrypted fields are decrypted before sending to the client (if authorized).
    WRITE: Plaintext fields are encrypted before saving to the database.
    
    document_key is only visible to admin users and is never encrypted.
    """
    def __init__(self, *args, **kwargs):
        self.force_decrypt = kwargs.pop('force_decrypt', False)
        super().__init__(*args, **kwargs)
    
    created_by   = UserSerializer(read_only=True)
    assigned_to  = UserSerializer(read_only=True)
    assigned_to_id = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(), source='assigned_to', write_only=True, required=False, allow_null=True
    )
    logs    = DocumentLogSerializer(many=True, read_only=True)
    qr_code = QRCodeSerializer(read_only=True)
    attachments = DocumentAttachmentSerializer(many=True, read_only=True)
    unlocked = serializers.SerializerMethodField()
    document_key = serializers.SerializerMethodField()  # Only shown to admins
    frontend_encrypted = serializers.BooleanField(write_only=True, required=False, default=False)

    def get_unlocked(self, instance):
        request = self.context.get('request') if self.context else None
        if not request:
            return False
        role = getattr(getattr(request.user, 'profile', None), 'role', 'viewer')
        if role in ('admin', 'staff'):
            return True
        # For viewers, unlocked is set by unlock endpoint
        return False
    
    def get_document_key(self, instance):
        """Only return document_key to admin users. It is never encrypted."""
        request = self.context.get('request') if self.context else None
        if not request:
            return None
        role = getattr(getattr(request.user, 'profile', None), 'role', 'viewer')
        if role == 'admin':
            return instance.document_key
        return None
    
    def _should_decrypt(self, instance):
        """Check if the current request has permission to decrypt encrypted fields."""
        # If force_decrypt is set, always decrypt
        if getattr(self, 'force_decrypt', False):
            return True
            
        request = self.context.get('request') if self.context else None
        if not request:
            return False
        role = getattr(getattr(request.user, 'profile', None), 'role', 'viewer')
        if role in ('admin', 'staff'):
            return True
        key_from_query = (request.query_params.get('key') or '').strip()
        stored_key = instance.document_key or ''
        return bool(key_from_query == stored_key)
    
    class Meta:
        model = Document
        fields = [
            'id', 'document_code', 'title', 'category', 'status',
            'description', 'notes', 'created_by', 'assigned_to',
            'assigned_to_id', 'created_at', 'updated_at', 'due_date',
            'location', 'is_encrypted', 'unlocked', 'document_key', 'frontend_encrypted', 'attachments', 'logs', 'qr_code'
        ]
        read_only_fields = ['document_code', 'created_by', 'created_at', 'updated_at']
    
    def to_representation(self, instance):
        """Override to decrypt IDEA-encrypted fields before returning data."""
        data = super().to_representation(instance)
        
        can_decrypt = self._should_decrypt(instance)
        role = getattr(getattr(self.context.get('request').user, 'profile', None), 'role', 'viewer') if self.context.get('request') else 'viewer'
        key_from_query = (self.context.get('request').query_params.get('key') or '').strip() if self.context.get('request') else ''

        if instance.is_encrypted and role not in ('admin', 'staff') and not can_decrypt:
            if key_from_query and key_from_query == instance.document_key:
                # Return encrypted data for frontend to decrypt
                data['title'] = instance.title
                data['description'] = instance.description or ''
                data['notes'] = instance.notes or ''
                data['location'] = instance.location or ''
                data['unlocked'] = True
            else:
                data['title'] = instance.title
                data['description'] = instance.description or ''
                data['notes'] = instance.notes or ''
                data['location'] = instance.location or ''
                data['unlocked'] = False
        else:
            if instance.is_encrypted:
                data['title']       = decrypt_document_field(instance.title)
                data['description'] = decrypt_document_field(instance.description or '')
                data['notes']       = decrypt_document_field(instance.notes or '')
                data['location']    = decrypt_document_field(instance.location or '') if instance.location else ''
            data['unlocked'] = True

        return data
    
    def create(self, validated_data):
        """Encrypt sensitive fields before saving a new document."""
        frontend_encrypted = validated_data.pop('frontend_encrypted', False)
        if not frontend_encrypted:
            validated_data['title']       = encrypt_document_field(validated_data.get('title', ''))
            validated_data['description'] = encrypt_document_field(validated_data.get('description', '') or '')
            validated_data['notes']       = encrypt_document_field(validated_data.get('notes', '') or '')
            location = validated_data.get('location')
            if location:
                validated_data['location'] = encrypt_document_field(location)
        validated_data['is_encrypted'] = True
        
        # Auto-generate a unique document code: CIT-YYYY-NNNN
        from django.utils import timezone
        year  = timezone.now().year
        count = Document.objects.filter(created_at__year=year).count() + 1
        validated_data['document_code'] = f"CIT-{year}-{count:04d}"
        
        return super().create(validated_data)
    
    def update(self, instance, validated_data):
        """Encrypt sensitive fields before updating an existing document."""
        frontend_encrypted = validated_data.pop('frontend_encrypted', False)
        if 'title' in validated_data and not frontend_encrypted:
            validated_data['title'] = encrypt_document_field(validated_data['title'])
        if 'description' in validated_data and not frontend_encrypted:
            validated_data['description'] = encrypt_document_field(validated_data.get('description', '') or '')
        if 'notes' in validated_data and not frontend_encrypted:
            validated_data['notes'] = encrypt_document_field(validated_data.get('notes', '') or '')
        if 'location' in validated_data and not frontend_encrypted:
            location = validated_data.get('location')
            if location:
                validated_data['location'] = encrypt_document_field(location)
            else:
                validated_data['location'] = None
        
        return super().update(instance, validated_data)