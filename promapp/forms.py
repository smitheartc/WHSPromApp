from django import forms

class StudentForm(forms.Form):
    SHIRT_SIZES = (
        ('S', 'Small'),
        ('M', 'Medium'),
        ('L', 'Large'),
        ('XL', 'Extra Large'),
        ('XXL', 'Double Extra Large'),
        ('XXXL', 'Triple Extra Large')
    )
    shirt_size = forms.ChoiceField(label='Shirt Size',choices=SHIRT_SIZES)
    date_email = forms.EmailField(label='Date Email (If not WISD)')

class DateCreationForm(forms.Form):
    SHIRT_SIZES = (
        ('S', 'Small'),
        ('M', 'Medium'),
        ('L', 'Large'),
        ('XL', 'Extra Large'),
        ('XXL', 'Double Extra Large'),
        ('XXXL', 'Triple Extra Large')
    )
    shirt_size = forms.ChoiceField(label='Shirt Size',choices=SHIRT_SIZES)
    email = forms.EmailField(label='Your Email')
    picture = forms.ImageField()
    first_name = forms.CharField(max_length=64)
    last_name = forms.CharField(max_length=64)
    public_school = forms.BooleanField(required=False)
    not_minor = forms.BooleanField(required=False)
    permission_email = forms.EmailField()
    tos = forms.BooleanField()

class DateApprovalForm(forms.Form):
    contact_email = forms.EmailField()
    approve = forms.BooleanField(required=False)

class UpdateStudentForm(forms.Form):
    first_name = forms.CharField(max_length=50)
    last_name = forms.CharField(max_length=50)
    date_email = forms.EmailField()
    ap_email = forms.EmailField(required=False)
    paid = forms.BooleanField(required=False)
    picture = forms.ImageField(required=False)
    received_ticket = forms.BooleanField(required=False)
    received_shirt = forms.BooleanField(required=False)
    ticket_num = forms.CharField(max_length=50, required=False)
    SHIRT_SIZES = (
        ('XS', 'Extra Small'),
        ('S', 'Small'),
        ('M', 'Medium'),
        ('L', 'Large'),
        ('XL', 'Extra Large'),
        ('XXL', 'Double Extra Large'),
        ('XXXL', 'Triple Extra Large')
    )
    shirt_size = forms.ChoiceField(label='Shirt Size',choices=SHIRT_SIZES)
    ap_approved = forms.BooleanField(required=False)
    wisd_approved = forms.BooleanField(required=False)