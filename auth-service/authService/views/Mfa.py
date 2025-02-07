from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
import pyotp
import qrcode
from io import BytesIO
import base64

@api_view(['GET'])
@permission_classes([IsAuthenticated])  # L'utilisateur doit être authentifié
def enable_2fa(request):
    """
    Génère la clé secrète et le QR code pour l'activation de la 2FA.
    """
    user = request.user

    if user.otp_secret:
        return Response(
            {"detail": "2FA is already enabled."},
            status=status.HTTP_400_BAD_REQUEST
        )

    # Générer une clé secrète OTP unique (mais ne pas l'enregistrer encore)
    otp_secret = pyotp.random_base32()

    # URL pour l'application d'authentification
    otp_uri = pyotp.totp.TOTP(otp_secret).provisioning_uri(
        name=user.email,
        issuer_name="Pongo"
    )

    # Générer le QR code
    qr = qrcode.QRCode(box_size=10, border=4)
    qr.add_data(otp_uri)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')

    # Convertir l'image en base64
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()

    # Retourner le QR code et la clé temporaire (à envoyer dans `verify_2fa`)
    return Response({
        "qr_code": qr_code_base64,
        "otp_secret": otp_secret,  # À envoyer avec `verify_2fa`
        "detail": "Scan this QR code and enter the first OTP to confirm activation."
    }, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def verify_2fa(request):
    """
    Vérifie le code OTP fourni par l'utilisateur et active la 2FA définitivement.
    """
    user = request.user
    otp_code = request.data.get("otp")
    otp_secret = request.data.get("otp_secret")  # Récupérer la clé temporaire

    if not otp_secret:
        return Response(
            {"detail": "OTP secret is required."},
            status=status.HTTP_400_BAD_REQUEST
        )

    # Vérifier le code OTP
    totp = pyotp.TOTP(otp_secret)
    if totp.verify(otp_code):
        # ✅ Si le code est valide, on enregistre la clé
        user.otp_secret = otp_secret
        user.save()
        return Response({"detail": "2FA enabled successfully."}, status=status.HTTP_200_OK)
    else:
        return Response({"detail": "Invalid OTP code."}, status=status.HTTP_400_BAD_REQUEST)



@api_view(['DELETE'])
@permission_classes([IsAuthenticated])  # L'utilisateur doit être authentifié
def disable_2fa(request):
    """
    Désactive la 2FA en supprimant le champ `otp_secret`.
    """
    user = request.user

    if not user.otp_secret:
        return Response(
            {"detail": "2FA is not enabled."},
            status=status.HTTP_400_BAD_REQUEST
        )

    # Supprimer le secret OTP
    user.otp_secret = None
    user.save()

    return Response({"detail": "2FA disabled successfully."}, status=status.HTTP_200_OK)
