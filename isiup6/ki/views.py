from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.contrib import messages
from .forms import UserForm, PersonalInfoForm, MedicalInfoForm, BiometricDataForm
from hashfunctions import cryptoHasher
from .models import User, DataRequest
from .forms import DataRequestForm
from django.core.files.storage import default_storage
import os
from django.http import HttpResponse
import datetime
from django.http import FileResponse
from .utils import handle_request, handle_request_approval
from .utils import generate_symmetric_key, encrypt_with_public_key, decrypt_with_private_key
from django.core.mail import send_mail


EncryptionAlgo = "DES"

hasher = cryptoHasher.Hasher()


# Your view remains the same
def upload_success(request):
    return render(request, "ki/upload_success.html")


def login_view(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        print(username, password)

        user = authenticate(request, username=username, password=password)
        print(user)
        if user is not None:
            login(request, user)
            return redirect("profile")
        else:
            messages.error(request, "Invalid username or password. Please try again.")

    return render(request, "ki/login.html")


def download_data(request, file_type):
    if request.user.is_authenticated:
        current_user = request.user
        file = None
        content_type = None

        if file_type == 'id_card_image':
            # Download ID Card Image
            decryped, decrypted_path = hasher.decryptFile(current_user.id_card_image.path, EncryptionAlgo, ".png", key=current_user.password)
            content_type = "image/enc"  # Adjust the content type accordingly

        elif file_type == 'informasi_medis_file':
            # Download Medical Info File
            decryped, decrypted_path = hasher.decryptFile(current_user.medicalinfo.informasi_medis_file.path, EncryptionAlgo, ".pdf", key=current_user.password)
            content_type = "application/enc"  # Adjust the content type accordingly

        elif file_type == 'sidik_jari_image':
            # Download Fingerprint Image
            decryped, decrypted_path = hasher.decryptFile(current_user.biometricdata.sidik_jari_image.path, EncryptionAlgo, ".mp4", key=current_user.password)
            content_type = "video/enc"  # Adjust the content type accordingly

        if decryped:
            response = HttpResponse(decryped, content_type=content_type)
            response['Content-Disposition'] = f'attachment; filename={decrypted_path}'
            return response

    return redirect("login")




def upload_data(request):
    if request.method == "POST":
        now = datetime.datetime.now()
        user_form = UserForm(request.POST, request.FILES)
        personal_info_form = PersonalInfoForm(request.POST)
        medical_info_form = MedicalInfoForm(request.POST, request.FILES)
        biometric_data_form = BiometricDataForm(request.POST, request.FILES)

        if (
            user_form.is_valid()
            and personal_info_form.is_valid()
            and medical_info_form.is_valid()
            and biometric_data_form.is_valid()
        ):
            # Save User data
            username = user_form.cleaned_data["username"]
            password = user_form.cleaned_data["password"]
            file = request.FILES["id_card_image"]

            file_name = default_storage.save("id_cards/" + file.name, file)
            print("File Name: ", file_name)

            path_to_file = os.path.abspath("media/" + file_name)
            print("Path to File: ", path_to_file)

            user = User.objects.create_user(
                username=username, password=password, id_card_image=path_to_file
            )

            # Save PersonalInfo data with the related User instance
            personal_info = personal_info_form.save(commit=False)
            personal_info.user = user
            personal_info.save()

            

             # Hash sensitive fields and save them back
            empty = ""
            personal_info.Full_Name = hasher.encryptText(personal_info.Full_Name, EncryptionAlgo, key=user.password)
            personal_info.Address = hasher.encryptText(personal_info.Address, EncryptionAlgo, key=user.password)
            personal_info.ID_Number = hasher.encryptText(personal_info.ID_Number, EncryptionAlgo, key=user.password)
            personal_info.Phone = hasher.encryptText(personal_info.Phone, EncryptionAlgo, key=user.password)
            personal_info.Email = hasher.encryptText(personal_info.Email, EncryptionAlgo, key=user.password)
            personal_info.umur = hasher.encryptText(personal_info.umur, EncryptionAlgo, key=user.password)
            personal_info.tanggal_lahir = hasher.encryptText(personal_info.tanggal_lahir, EncryptionAlgo, key=user.password)
            

            
            # Save the updated PersonalInfo
            personal_info.save()

            # Save MedicalInfo data with the related User instance
            
            medical_info = medical_info_form.save(commit=False)
            medical_info.user = user
            medical_info.save()

            medical_info.Job_Information = hasher.encryptText(medical_info.Job_Information, EncryptionAlgo, key=user.password)
            medical_info.informasi_medis_file = hasher.encryptFile(
                medical_info.informasi_medis_file.path,
                EncryptionAlgo,
                key=user.password,
            )
            medical_info.save()

            # Save BiometricData data with the related User instance
            biometric_data = biometric_data_form.save(commit=False)
            biometric_data.user = user
            biometric_data.save()

            biometric_data.sidik_jari_image = hasher.encryptFile(
                biometric_data.sidik_jari_image.path, EncryptionAlgo, key=user.password
            )
            biometric_data.save()

            # delete old files
            hasher.deleteFile(user.id_card_image.path, ".jpg")
            hasher.deleteFile(medical_info.informasi_medis_file.path, ".pdf")
            hasher.deleteFile(biometric_data.sidik_jari_image.path, ".mp4")
            # hasher.deleteFile(user.id_card_image.path, ".enc")
            # hasher.deleteFile(medical_info.informasi_medis_file.path, ".enc")
            # hasher.deleteFile(biometric_data.sidik_jari_image.path, ".enc")

            deltatime = datetime.datetime.now() - now
            print("Delta Time: ", deltatime.total_seconds())
            return redirect("upload_success")  # Replace with your success URL.

    else:
        user_form = UserForm()
        personal_info_form = PersonalInfoForm()
        medical_info_form = MedicalInfoForm()
        biometric_data_form = BiometricDataForm()

    return render(
        request,
        "ki/upload_data.html",
        {
            "user_form": user_form,
            "personal_info_form": personal_info_form,
            "medical_info_form": medical_info_form,
            "biometric_data_form": biometric_data_form,
        },
    )


@login_required
def profile(request):
    current_user = request.user

    # Get the user's data
    personal_info = User.objects.get(username=current_user.username).personalinfo
    medical_info = User.objects.get(username=current_user.username).medicalinfo
    biometric_data = User.objects.get(username=current_user.username).biometricdata

    # decrypt personal info with user's password
    personal_info.Full_Name = hasher.decryptText(personal_info.Full_Name, EncryptionAlgo, key=current_user.password)
    personal_info.Address = hasher.decryptText(personal_info.Address, EncryptionAlgo, key=current_user.password)
    personal_info.ID_Number = hasher.decryptText(personal_info.ID_Number, EncryptionAlgo, key=current_user.password)
    personal_info.Phone = hasher.decryptText(personal_info.Phone, EncryptionAlgo, key=current_user.password)
    personal_info.Email = hasher.decryptText(personal_info.Email, EncryptionAlgo, key=current_user.password)
    personal_info.umur = hasher.decryptText(personal_info.umur, EncryptionAlgo, key=current_user.password)
    personal_info.tanggal_lahir = hasher.decryptText(personal_info.tanggal_lahir, EncryptionAlgo, key=current_user.password)

    medical_info.Job_Information = hasher.decryptText(medical_info.Job_Information, EncryptionAlgo, key=current_user.password)

    return render(
        request,
        "ki/profile.html",
        {
            "personal_info": personal_info,
            "medical_info": medical_info,
            "biometric_data": biometric_data,
        },
    )

def view_all_data(request):
    # Retrieve all users excluding the current user
    all_users = User.objects.exclude(username=request.user.username)

    # Create empty lists to store data
    all_personal_info = []
    all_medical_info = []
    all_biometric_data = []

    # Loop through each user to collect data
    for user in all_users:
        all_personal_info.append(user.personalinfo)
        all_medical_info.append(user.medicalinfo)
        all_biometric_data.append(user.biometricdata)

    # Pass the data to the template
    context = {
        'all_personal_info': all_personal_info,
        'all_medical_info': all_medical_info,
        'all_biometric_data': all_biometric_data,
    }

    return render(request, 'ki/view_all_data.html', context)

def request_data(request, requested_user_id):
    if request.method == 'POST':
        requested_user = User.objects.get(id=requested_user_id)
        requesting_user = request.user

        # Generate symmetric key
        symmetric_key = hasher.get128BitKey(requesting_user.password)

        privateKey, publicKey = hasher.RSA_Generate_Key()

        # Encrypt symmetric key with requested user's public key
        encrypted_symmetric_key = hasher.RSA_Encrypt(publicKey, symmetric_key)

        print(hasher.RSA_Decrypt(privateKey, encrypted_symmetric_key))

        # Save the request with encrypted symmetric key
        DataRequest.objects.create(
            requesting_user=requesting_user,
            requested_user=requested_user,
            symmetric_key=symmetric_key,
            encrypted_symmetric_key=encrypted_symmetric_key
        )

        # Send email with the encrypted symmetric key to the requesting user
        send_encrypted_key_email(requested_user.email, encrypted_symmetric_key)


        return redirect('profile')

    return render(request, 'ki/request_data.html', {'requested_user_id': requested_user_id})

def handle_request_approval(request, request_id):
    request_instance = DataRequest.objects.get(id=request_id)

    # Decrypt the symmetric key with the user's private key
    symmetric_key = decrypt_with_private_key(request_instance.encrypted_symmetric_key, request_instance.requested_user.private_key)

    # Save the symmetric key in the request
    request_instance.symmetric_key = symmetric_key
    request_instance.is_approved = True
    request_instance.save()

    return redirect('profile')

def send_encrypted_key_email(to_email, encrypted_symmetric_key):
    # Add your email sending logic here
    # This is just a placeholder, replace it with your actual email sending code
    subject = 'Encrypted Symmetric Key'
    message = f'Here is the encrypted symmetric key: {encrypted_symmetric_key}'
    from_email = 'your@email.com'
    recipient_list = [to_email]

    send_mail(subject, message, from_email, recipient_list)

