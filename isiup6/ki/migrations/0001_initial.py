# Generated by Django 3.2.9 on 2023-10-08 14:49

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('username', models.CharField(max_length=100)),
                ('password', models.CharField(max_length=100)),
                ('id_card_image', models.ImageField(upload_to='id_cards/')),
            ],
        ),
        migrations.CreateModel(
            name='PersonalInfo',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('nama', models.CharField(max_length=255)),
                ('alamat', models.TextField()),
                ('no_ktp_paspor', models.CharField(max_length=20)),
                ('no_telepon', models.CharField(max_length=15)),
                ('email', models.EmailField(max_length=254)),
                ('umur', models.PositiveIntegerField()),
                ('tanggal_lahir', models.DateField()),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='ki.user')),
            ],
        ),
        migrations.CreateModel(
            name='MedicalInfo',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('informasi_pekerjaan', models.TextField()),
                ('informasi_medis_file', models.FileField(upload_to='medical_info/')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='ki.user')),
            ],
        ),
        migrations.CreateModel(
            name='BiometricData',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('sidik_jari_image', models.ImageField(upload_to='biometric_data/')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='ki.user')),
                
            ],
        ),
    ]
