# ki/admin.py

from django.contrib import admin
from .models import User, PersonalInfo, MedicalInfo, BiometricData

admin.site.register(User)
admin.site.register(PersonalInfo)
admin.site.register(MedicalInfo)
admin.site.register(BiometricData)
