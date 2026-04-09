from django.shortcuts import render
from django.http import HttpResponse

# Create your views here.
"""
API Views for CIT Document Tracker

Endpoints:
  POST   /api/register/          — Register a new user
  GET    /api/me/                 — Get current user info
  GET    /api/users/              — List all users (admin only)
  GET    /api/documents/          — List documents (filtered by role)
  POST   /api/documents/          — Create a new document
  GET    /api/documents/<id>/     — Document detail (with logs)
  PUT    /api/documents/<id>/     — Update document
  DELETE /api/documents/<id>/     — Delete document (admin only)
  POST   /api/documents/<id>/qr/  — Generate QR code for document
  GET    /api/dashboard/          — Dashboard statistics
"""

import secrets
import qrcode
import io
from django.core.files.base import ContentFile
from django.db.models import Q
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response

from .models import Document, DocumentLog, QRCode, UserProfile, DocumentAttachment
from .serializers import DocumentSerializer, RegisterSerializer, UserSerializer, DocumentAttachmentSerializer
from .permissions import get_user_role, IsAdminRole, IsStaffOrAdmin, ReadOnlyOrStaffAdmin
from .idea_encryption import DOCUMENT_KEY, idea_encrypt_bytes, idea_decrypt_bytes, encrypt_document_field, decrypt_document_field
from django.contrib.auth.models import User


@api_view(['POST'])
@permission_classes([AllowAny])
def register(request):
    """Register a new user with username, password, and role."""
    serializer = RegisterSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        return Response({'message': f'User {user.username} created successfully.'}, status=201)
    return Response(serializer.errors, status=400)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def me(request):
    """Return the currently authenticated user's data."""
    serializer = UserSerializer(request.user)
    return Response(serializer.data)


@api_view(['GET'])
@permission_classes([IsAdminRole])
def user_list(request):
    """List all users — Admin only."""
    users = User.objects.select_related('profile').all()
    serializer = UserSerializer(users, many=True)
    return Response(serializer.data)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def dashboard_stats(request):
    """
    Return aggregate stats for the dashboard.
    Admins see all documents; Staff/Viewer see only their assigned docs.
    """
    role = request.user.profile.role if hasattr(request.user, 'profile') else 'viewer'
    
    if role == 'admin':
        docs = Document.objects.all()
    elif role == 'staff':
        docs = Document.objects.filter(
            Q(created_by=request.user) | Q(assigned_to=request.user)
        )
    else:  # viewer
        docs = Document.objects.all()
    
    stats = {
        'total':     docs.count(),
        'pending':   docs.filter(status='pending').count(),
        'in_review': docs.filter(status='in_review').count(),
        'approved':  docs.filter(status='approved').count(),
        'rejected':  docs.filter(status='rejected').count(),
        'archived':  docs.filter(status='archived').count(),
    }
    return Response(stats)


@api_view(['GET', 'POST'])
@permission_classes([ReadOnlyOrStaffAdmin])
def document_list(request):
    """
    GET  — List documents based on user role + optional filters
    POST — Create a new document (staff/admin only)
    """
    if request.method == 'GET':
        role = getattr(getattr(request.user, 'profile', None), 'role', 'viewer')
        
        # Filter by role
        if role == 'admin':
            docs = Document.objects.all()
        elif role == 'staff':
            docs = Document.objects.filter(
                Q(created_by=request.user) | Q(assigned_to=request.user)
            )
        else:
            docs = Document.objects.all()
        
        # Apply search filters from query params
        search = request.query_params.get('search')
        status_filter = request.query_params.get('status')
        category_filter = request.query_params.get('category')
        
        if status_filter:
            docs = docs.filter(status=status_filter)
        if category_filter:
            docs = docs.filter(category=category_filter)
        
        serializer = DocumentSerializer(docs, many=True, context={'request': request})
        return Response(serializer.data)
    
    elif request.method == 'POST':
        serializer = DocumentSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            doc = serializer.save(created_by=request.user)
            # Log the creation action
            DocumentLog.objects.create(
                document=doc,
                action='created',
                performed_by=request.user,
                details=encrypt_document_field(f"Document {doc.document_code} created.")
            )
            return Response(DocumentSerializer(doc, context={'request': request}).data, status=201)
        return Response(serializer.errors, status=400)


@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([ReadOnlyOrStaffAdmin])
def document_detail(request, pk):
    """
    GET    — Retrieve a single document (with logs)
    PUT    — Update document (staff/admin)
    DELETE — Delete document (admin only)
    """
    try:
        doc = Document.objects.get(pk=pk)
    except Document.DoesNotExist:
        return Response({'error': 'Document not found.'}, status=404)
    
    if request.method == 'GET':
        # Log that the document was viewed
        DocumentLog.objects.create(
            document=doc, action='viewed',
            performed_by=request.user,
            details=encrypt_document_field(f"Viewed by {request.user.username}")
        )
        serializer = DocumentSerializer(doc, context={'request': request})
        return Response(serializer.data)
    
    elif request.method == 'PUT':
        old_status = doc.status
        serializer = DocumentSerializer(doc, data=request.data, partial=True, context={'request': request})
        if serializer.is_valid():
            updated_doc = serializer.save()
            # Log status change if status was modified
            if old_status != updated_doc.status:
                DocumentLog.objects.create(
                    document=updated_doc, action='status_change',
                    performed_by=request.user,
                    details=encrypt_document_field(f"Status changed from {old_status} to {updated_doc.status}")
                )
            else:
                DocumentLog.objects.create(
                    document=updated_doc, action='updated',
                    performed_by=request.user,
                    details=encrypt_document_field("Document updated.")
                )
            return Response(DocumentSerializer(updated_doc).data)
        return Response(serializer.errors, status=400)
    
    elif request.method == 'DELETE':
        # Only admins can delete
        if not hasattr(request.user, 'profile') or request.user.profile.role != 'admin':
            return Response({'error': 'Only admins can delete documents.'}, status=403)
        DocumentLog.objects.create(
            document=doc, action='deleted',
            performed_by=request.user,
            details=encrypt_document_field(f"Document {doc.document_code} deleted.")
        )
        doc.delete()
        return Response({'message': 'Document deleted.'}, status=204)


@api_view(['POST'])
@permission_classes([IsStaffOrAdmin])
def generate_qr(request, pk):
    """
    Generate a QR code for a document.
    
    The QR code encodes a URL like:
      http://localhost:3000/documents/<id>
    
    The QR image is stored as a PNG file and linked to the document.
    """
    try:
        doc = Document.objects.get(pk=pk)
    except Document.DoesNotExist:
        return Response({'error': 'Document not found.'}, status=404)
    
    # Build the URL to embed in the QR code. It includes the document access key.
    frontend_url = f"http://localhost:3000/documents/{doc.id}?key={doc.document_key}"
    
    # Generate QR code image using the qrcode library
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_H,  # High error correction
        box_size=10,
        border=4,
    )
    qr.add_data(frontend_url)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Save the image to an in-memory buffer
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    
    # Save or update the QRCode record linked to this document
    qr_obj, created = QRCode.objects.update_or_create(
        document=doc,
        defaults={
            'encoded_url': frontend_url,
            'generated_by': request.user,
        }
    )
    qr_obj.image.save(f'qr_{doc.document_code}.png', ContentFile(buffer.read()), save=True)
    
    # Log the QR generation action
    DocumentLog.objects.create(
        document=doc, action='qr_generated',
        performed_by=request.user,
        details=encrypt_document_field(f"QR code generated by {request.user.username}")
    )
    
    return Response({
        'message': 'QR code generated.',
        'qr_url': request.build_absolute_uri(qr_obj.image.url),
        'encoded_url': frontend_url,
        'document_key': doc.document_key
    })


@api_view(['POST'])
@permission_classes([IsStaffOrAdmin])
def document_attachment_upload(request, pk):
    """Upload an encrypted file attachment to a document."""
    try:
        doc = Document.objects.get(pk=pk)
    except Document.DoesNotExist:
        return Response({'error': 'Document not found.'}, status=404)

    attachment_file = request.FILES.get('file')
    if not attachment_file:
        return Response({'error': 'No file provided.'}, status=400)

    raw_bytes = attachment_file.read()
    try:
        encrypted_bytes = idea_encrypt_bytes(raw_bytes, DOCUMENT_KEY)
    except Exception as exc:
        return Response({'error': str(exc)}, status=400)

    attachment = DocumentAttachment(
        document=doc,
        original_name=attachment_file.name,
        uploaded_by=request.user,
    )
    attachment.file.save(attachment_file.name, ContentFile(encrypted_bytes), save=True)
    attachment.save()

    DocumentLog.objects.create(
        document=doc, action='updated',
        performed_by=request.user,
        details=encrypt_document_field(f"Attachment {attachment.original_name} uploaded.")
    )
    serializer = DocumentAttachmentSerializer(attachment, context={'request': request})
    return Response(serializer.data, status=201)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def document_attachment_download(request, pk, attachment_pk):
    """Download and decrypt an attachment if the user is authorized."""
    try:
        doc = Document.objects.get(pk=pk)
        attachment = DocumentAttachment.objects.get(pk=attachment_pk, document=doc)
    except (Document.DoesNotExist, DocumentAttachment.DoesNotExist):
        return Response({'error': 'Attachment not found.'}, status=404)

    role = get_user_role(request.user)
    if role not in ('admin', 'staff'):
        key = request.query_params.get('key')
        if key != doc.document_key:
            return Response({'error': 'Unauthorized to download this attachment.'}, status=403)

    encrypted_data = attachment.file.read()
    try:
        decrypted_data = idea_decrypt_bytes(encrypted_data, DOCUMENT_KEY)
    except Exception:
        return Response({'error': 'Failed to decrypt attachment.'}, status=500)

    response = HttpResponse(decrypted_data, content_type='application/octet-stream')
    response['Content-Disposition'] = f'attachment; filename="{attachment.original_name}"'
    return response


@api_view(['GET'])
@permission_classes([IsAdminRole])
def document_key_debug(request, pk):
    """Debug endpoint to show document key (admin only)."""
    try:
        doc = Document.objects.get(pk=pk)
    except Document.DoesNotExist:
        return Response({'error': 'Document not found.'}, status=404)
    
    return Response({
        'document_code': doc.document_code,
        'document_key': doc.document_key,
        'has_key': bool(doc.document_key),
        'key_length': len(doc.document_key) if doc.document_key else 0
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def document_unlock(request, pk):
    """Unlock a document by validating the provided access key."""
    try:
        doc = Document.objects.get(pk=pk)
    except Document.DoesNotExist:
        return Response({'error': 'Document not found.'}, status=404)

    # Ensure document has a key (generate if missing)
    if not doc.document_key:
        doc.document_key = secrets.token_urlsafe(24)
        doc.save()

    access_key = request.data.get('key', '').strip()  # Strip whitespace
    stored_key = doc.document_key or ''

    if not access_key or access_key != stored_key:
        return Response({'error': 'Invalid access key.'}, status=403)

    # Return decrypted fields after successful unlock
    serializer = DocumentSerializer(doc, context={'request': request}, force_decrypt=True)
    data = serializer.data

    # Mark as unlocked so frontend knows to decrypt
    data['unlocked'] = True

    return Response(data)