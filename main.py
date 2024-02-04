from PIL import Image, ImageDraw, ImageFont
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


def generer_cle_prive_publique():
    # Générer une paire de clés RSA de 2048 bits
    key = RSA.generate(2048)

    # Récupérer les clés privée et publique
    cle_privee = key.export_key()
    cle_publique = key.publickey().export_key()

    # Sauvegarder les clés dans des fichiers (facultatif)
    with open("cle_privee.pem", "wb") as fichier_cle_privee:
        fichier_cle_privee.write(cle_privee)

    with open("cle_publique.pem", "wb") as fichier_cle_publique:
        fichier_cle_publique.write(cle_publique)

    return cle_privee, cle_publique


def signer_donnees(cle_privee, donnees):
    key = RSA.import_key(cle_privee)
    hachage = SHA256.new(donnees)
    signature = pkcs1_15.new(key).sign(hachage)
    return signature


def verifier_signature(cle_publique, donnees, signature):
    key = RSA.import_key(cle_publique)
    hachage = SHA256.new(donnees)
    try:
        pkcs1_15.new(key).verify(hachage, signature)
        return True
    except (ValueError, TypeError):
        return False


def invert_half(img):
    m = img.height // 2  # milieu de l'image
    pixels = img.load()  # tableau des pixels

    for y in range(m, img.height):
        for x in range(0, img.width):
            r, g, b = pixels[x, y]  # on récupère les composantes RGB du pixel (x,m)
            r = r ^ 0b11111111  # on les inverse bit à bit avec un XOR
            g = g ^ 0b11111111  # ...
            b = b ^ 0b11111111  # ...
            pixels[x, y] = r, g, b  # on remet les pixels inversés dans le tableau


def cacher_message(image_path, message, image_output_path):
    # Ouvrir l'image
    image = Image.open(image_path)

    # Convertir le message en binaire
    message_binaire = ''.join(format(ord(char), '08b') for char in str(message))

    # Ajouter un délimiteur de fin au message
    message_binaire += '1111111111111110'

    # Obtenir les pixels de l'image
    pixels = list(image.getdata())

    # Modifier les bits de chaque pixel pour incorporer le message
    nouvelle_image_pixels = []
    index_message = 0

    for pixel in pixels:
        if index_message < len(message_binaire):
            # Convertir chaque composante (R, G, B) en binaire
            pixel_binaire = [format(component, '08b') for component in pixel]

            # Modifier le dernier bit de chaque composante pour incorporer le message
            for i in range(3):
                pixel_binaire[i] = pixel_binaire[i][:-1] + message_binaire[index_message]
                index_message += 1
                if index_message == len(message_binaire):
                    break

            # Convertir les composantes binaires en entiers
            nouvelle_image_pixels.append(tuple(int(component, 2) for component in pixel_binaire))
        else:
            nouvelle_image_pixels.append(pixel)

    # Créer une nouvelle image avec les pixels modifiés
    nouvelle_image = Image.new(image.mode, image.size)
    nouvelle_image.putdata(nouvelle_image_pixels)
    nouvelle_image.save(image_output_path)


def extraire_message(image_path):
    # Ouvrir l'image
    image = Image.open(image_path)

    # Obtenir les pixels de l'image
    pixels = list(image.getdata())

    # Extraire les bits du message caché
    message_binaire = ''
    for pixel in pixels:
        for i in range(3):
            message_binaire += format(pixel[i], '08b')[-1]

    # Trouver le délimiteur de fin dans le message binaire
    index_delimiteur = message_binaire.find('1111111111111110')

    # Extraire le message binaire sans le délimiteur de fin
    message_binaire = message_binaire[:index_delimiteur]

    # Convertir le message binaire en texte
    message = ''.join(chr(int(message_binaire[i:i + 8], 2)) for i in range(0, len(message_binaire), 8))

    return message


def genere_diplome(nom, prenom, date, filiere, mention):
    # Ouvrir le modèle de diplôme
    diplome = Image.open('./input/diploma1.png')

    # Ajouter le texte
    def draw_text(diplome, text, y, size=10):
        center = diplome.width
        draw = ImageDraw.Draw(diplome)
        font = ImageFont.truetype('arial.ttf', size=size)
        w = draw.textlength(text, font)  # Draw the text in the center of the image
        draw.text(((center - w) // 2, y), text, fill='black', font=font)

    draw_text(diplome, 'Diplôme de licence en ' + filiere, 100, 30)
    font_petit_texte = 15
    draw_text(diplome, 'Vu la loi du 01/01/1997 portant organisation de l’enseignement inférieur', 150,
              font_petit_texte)
    draw_text(diplome, 'Le diplôme de licence en ' + filiere, 190, font_petit_texte)
    draw_text(diplome, 'est délivré à ' + (nom + ' ' + prenom).title(), 205, font_petit_texte)
    draw_text(diplome, 'né(e) le ' + date, 220, font_petit_texte)
    draw_text(diplome, 'Avec mention : ' + mention, 235, font_petit_texte)
    draw_text(diplome, 'Fait à ici le ' + date, 250, font_petit_texte)

    # Sauvegarder le diplôme
    diplome.save('./output/diplome_' + nom + '_' + prenom + '.png')


def convert_img_to_base64(img_path):
    import base64
    import pyperclip
    with open(img_path, "rb") as image_file:
        encoded_string = base64.b64encode(image_file.read())
        return encoded_string


def save_img_from_base64(base64_string, img_save_path):
    import base64
    with open(img_save_path, "wb") as image_file:
        encoded_bytes = base64.b64decode(base64_string)
        image_file.write(encoded_bytes)


def gen_qr_code(nom, prenom, date, filiere, moyenne, img_save_path):
    import qrcode
    data = (nom + '#' + prenom + '#' + date + '#' + filiere + '#' + str(moyenne))
    # Create qr code instance with big amount of data
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(img_save_path)


def difference_image(img_path1, img_path2, diffimg):
    from PIL import ImageChops
    img1 = Image.open(img_path1)
    img2 = Image.open(img_path2)
    diff = ImageChops.difference(img1, img2)
    # threshold the difference image
    threshold = 1
    diff = diff.point(lambda x: 0 if x < threshold else 255)
    diff.save(diffimg)


def fuze_image(img_path1, img_path2, img_save_path):
    from PIL import Image, ImageChops
    img1 = Image.open(img_path1)
    img2 = Image.open(img_path2)
    img2 = img2.resize((img1.width//6, img1.height//6))
    # inverse la couleur de l'image 2
    img2 = ImageChops.invert(img2)
    # Coller l'image 2 sur l'image 1 avec un masque transparent
    mask = Image.new("L", img2.size, 1)
    img1.paste(img2, ((img1.width - img2.width)-75, (img1.height - img2.height)-75), mask)
    img1.save(img_save_path)


def main(filename, output):
    # img = Image.open(filename)  # ouverture de l'image contenue dans un fichier
    # invert_half(img)
    # img.save(output)  # sauvegarde de l'image obtenue dans un autre fichier

    # Exemple d'utilisation
    image_path = 'image.jpg'
    message_a_cacher = 'Ceci est un message secret!'

    # Cacher le message dans l'image
    cacher_message(filename, message_a_cacher, output)

    # Extraire le message de l'image cachée
    message_extrait = extraire_message(output)
    print("Message extrait :", message_extrait)


if __name__ == "__main__":
    import sys

    if sys.argv[1] == "invert_half":
        img = Image.open(sys.argv[2])
        invert_half(img)
        img.save(sys.argv[3])
        sys.exit(0)

    elif sys.argv[1] == "cacher_message":
        cacher_message(sys.argv[2], sys.argv[3], sys.argv[4])
        sys.exit(0)

    elif sys.argv[1] == "genere_diplome":
        genere_diplome(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6])
        sys.exit(0)

    elif sys.argv[1] == "qr_code":
        import qrcode

        img = qrcode.make(sys.argv[2])
        img.save(sys.argv[3])
        sys.exit(0)

    elif sys.argv[1] == "convert_img_to_base64":
        convert_img_to_base64(sys.argv[2])
        sys.exit(0)

    elif sys.argv[1] == "gen_qr_code":
        gen_qr_code(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], sys.argv[7])
        sys.exit(0)

    elif sys.argv[1] == "difference_image":
        difference_image(sys.argv[2], sys.argv[3], sys.argv[4])
        sys.exit(0)

    elif sys.argv[1] == "fuze_image":
        fuze_image(sys.argv[2], sys.argv[3], sys.argv[4])
        sys.exit(0)

    elif sys.argv[1] == "super_diplome":
        # Variables
        nom = sys.argv[2]
        prenom = sys.argv[3]
        date = sys.argv[4]
        filiere = sys.argv[5]
        mention = sys.argv[6]
        moyenne = sys.argv[7]
        image = sys.argv[8]

        # Paths
        orig_dipl_path = './output/diplome_' + nom + '_' + prenom + '.png'
        work_path = './output/work_' + nom + '_' + prenom + '.png'
        qrcode_path = './output/qr_code_' + nom + '_' + prenom + '.png'
        final_path = './output/super_diplome_' + nom + '_' + prenom + '.png'

        # Generate
        genere_diplome(nom, prenom, date, filiere, mention)
        gen_qr_code(nom, prenom, date, filiere, moyenne, qrcode_path)

        # Cacher le l'image en base64 dans le diplome et cacher le qr code dans le diplome
        cacher_message(orig_dipl_path, convert_img_to_base64(image), work_path)
        fuze_image(work_path, qrcode_path, final_path)

        sys.exit(0)

    elif sys.argv[1] == "verif_diplome":
        # Variables
        diplome_path = sys.argv[2]
        output_path = './output/' + sys.argv[3] + '.png'
        output1_path = './output/' + sys.argv[3] + '1.png'
        res = extraire_message(diplome_path)
        save_img_from_base64(res, output_path)
        difference_image('./input/diploma1.png', diplome_path, output1_path)
        sys.exit(0)

    if len(sys.argv) != 3:
        print("usage: {} image output".format(sys.argv[0]))
        sys.exit(1)

    main(sys.argv[1], sys.argv[2])

    # # Exemple d'utilisation
    # cle_privee, cle_publique = generer_cle_prive_publique()
    #
    # donnees_a_signer = b"Les donnees que vous voulez signer"
    # signature = signer_donnees(cle_privee, donnees_a_signer)
    #
    # # Simuler une modification des données
    # # donnees_modifiees = b"Les donnees modifiees"
    # donnees_modifiees = b"Les donnees que vous voulez signer"
    # verification = verifier_signature(cle_publique, donnees_modifiees, signature)
    #
    # if verification:
    #     print("La signature est valide.")
    # else:
    #     print("La signature n'est pas valide.")
