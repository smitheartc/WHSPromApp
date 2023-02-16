from django.db import models

# Create your models here.

class Student(models.Model):
    SHIRT_SIZES = (
        ('XS', 'Extra Small'),
        ('S', 'Small'),
        ('M', 'Medium'),
        ('L', 'Large'),
        ('XL', 'Extra Large'),
        ('XXL', 'Double Extra Large'),
        ('XXXL', 'Triple Extra Large')
    )
    first_name = models.CharField(max_length=30, null=True)
    last_name = models.CharField(max_length=30, null=True)
    email = models.EmailField(unique=True)
    shirtSize = models.CharField(max_length=4, choices=SHIRT_SIZES)
    dateEmail = models.EmailField(null=True)
    picture = models.ImageField(null=True, upload_to="user_pictures/")
    minor = models.BooleanField()
    public_school = models.BooleanField()
    isWisd = models.BooleanField()
    paid = models.BooleanField()
    ap_approved = models.BooleanField()
    ap_email = models.EmailField()
    wisd_approved = models.BooleanField()
    received_ticket = models.BooleanField()
    ticket_num = models.CharField(max_length=50)
    checked_in = models.BooleanField()
    received_shirt = models.BooleanField()


class EmailData(models.Model):
    email = models.EmailField()
    wisd_date = models.EmailField()
    key = models.CharField(max_length=50)

class ApprovalEmailData(models.Model):
    date_email = models.EmailField()
    ap_email = models.EmailField()
    key = models.CharField(max_length=50)
