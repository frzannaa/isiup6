from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from hashfunctions import cryptoHasher
from django.core.exceptions import ValidationError

#change the algorithm here (type manually)
EncryptionAlgo = "AES"

class CustomUserManager(BaseUserManager):
    def create_user(self, username, password=None, id_card_image=None):
        if not username:
            raise ValueError('The Username field must be set')

        user = self.model(username=username)
        user.set_password(password)
        user.save()
        hasher = cryptoHasher.Hasher()
        user.id_card_image = hasher.encryptFile(id_card_image, EncryptionAlgo, key=user.password)
        user.save()

        return user

    def create_superuser(self, username, password):
        user = self.create_user(username=username, password=password)
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user


class User(AbstractBaseUser):
    REQUIRED_FIELDS = ('user',)

    USERNAME_FIELD = 'username'
    objects = CustomUserManager()

    username = models.CharField(max_length=100, unique=True)
    password = models.CharField(max_length=100)
    id_card_image = models.ImageField(upload_to="id_cards/")

    def __str__(self):
        return self.username
    
    public_key = models.TextField(blank=True, null=True)
    private_key = models.TextField(blank=True, null=True)

    @property
    def email(self):
        # Access the email from the related PersonalInfo
        return self.personalinfo.Email


class PersonalInfo(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    Full_Name = models.CharField(max_length=255)
    Address = models.TextField()
    ID_Number = models.CharField(max_length=20)
    Phone = models.CharField(max_length=15)
    Email = models.EmailField()
    umur = models.CharField(max_length=2)  # Kolom untuk umur
    tanggal_lahir = models.CharField(max_length=8)  # Kolom untuk tanggal lahir

    def __str__(self):
        return self.Full_Name

def validate_file_extension(value):
    import os
    from django.core.exceptions import ValidationError

    ext = os.path.splitext(value.name)[1]  # Get the file extension
    valid_extensions = [".pdf", ".xls", ".doc"]

    if not ext.lower() in valid_extensions:
        raise ValidationError(
            "Unsupported file type. Please upload a PDF, XLS, or DOC file."
        )

class MedicalInfo(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    Job_Information = models.TextField()  # Informasi pekerjaan saat ini
    informasi_medis_file = models.FileField(
        upload_to="medical_info/", validators=[validate_file_extension]
    )

def validate_video_file(value):
    import os

    ext = os.path.splitext(value.name)[1]  # Get the file extension
    valid_extensions = [".mp4", ".avi", ".mov", ".mkv"]  # Add or modify extensions as needed

    if not ext.lower() in valid_extensions:
        raise ValidationError(
            "Unsupported file type. Please upload a video file with extensions: mp4, avi, mov, mkv."
        )


class BiometricData(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    sidik_jari_image = models.ImageField(
        upload_to="biometric_data/", validators=[validate_video_file]
    )  # Kolom untuk sidik jari (image)

class DataRequest(models.Model):
    requesting_user = models.ForeignKey(User, related_name='requests_sent', on_delete=models.CASCADE)
    requested_user = models.ForeignKey(User, related_name='requests_received', on_delete=models.CASCADE)
    is_approved = models.BooleanField(default=False)
    symmetric_key = models.BinaryField(null=True, blank=True)
    encrypted_symmetric_key = models.BinaryField(null=True, blank=True)

