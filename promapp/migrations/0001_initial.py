# Generated by Django 4.0.3 on 2022-03-22 19:16

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='ApprovalEmailData',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('date_email', models.EmailField(max_length=254, unique=True)),
                ('ap_email', models.EmailField(max_length=254)),
                ('key', models.CharField(max_length=50)),
            ],
        ),
        migrations.CreateModel(
            name='EmailData',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('email', models.EmailField(max_length=254, unique=True)),
                ('wisd_date', models.EmailField(max_length=254)),
                ('key', models.CharField(max_length=50)),
            ],
        ),
        migrations.CreateModel(
            name='Student',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('first_name', models.CharField(max_length=30, null=True)),
                ('last_name', models.CharField(max_length=30, null=True)),
                ('email', models.EmailField(max_length=254, unique=True)),
                ('shirtSize', models.CharField(choices=[('XS', 'Extra Small'), ('S', 'Small'), ('M', 'Medium'), ('L', 'Large'), ('XL', 'Extra Large'), ('XXL', 'Double Extra Large'), ('XXXL', 'Triple Extra Large')], max_length=4)),
                ('dateEmail', models.EmailField(max_length=254, null=True, unique=True)),
                ('picture', models.ImageField(null=True, upload_to='user_pictures/')),
                ('minor', models.BooleanField()),
                ('public_school', models.BooleanField()),
                ('isWisd', models.BooleanField()),
                ('paid', models.BooleanField()),
                ('ap_approved', models.BooleanField()),
                ('ap_email', models.EmailField(max_length=254)),
                ('wisd_approved', models.BooleanField()),
                ('received_ticket', models.BooleanField()),
                ('ticket_num', models.CharField(max_length=50)),
                ('checked_in', models.BooleanField()),
                ('received_shirt', models.BooleanField()),
            ],
        ),
    ]
