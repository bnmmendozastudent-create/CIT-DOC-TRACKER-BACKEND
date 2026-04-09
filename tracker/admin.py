from django.contrib import admin
from .models import UserProfile, Document, DocumentLog, QRCode

admin.site.register(UserProfile)
admin.site.register(Document)
admin.site.register(DocumentLog)
admin.site.register(QRCode)
