from flask import Flask, render_template, request

import pymongo

from pymongo import MongoClient

from config import Config

# Ivans code

## Import all the necessary libraries for the code
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend



def encrypt_message(plaintext, public_key):
    ciphertext = public_key.encrypt(
        plaintext.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode('utf-8')  # Convert to base64 string

encrypt_message("12345", Config.ca_public_key)

Private_key = "3082025e02010002818100e25596bc81918822c7287eb3d5446a5456cb45f7f980cecf6c8750b82e7e03f0e523f4156e5ec6f33b2b5be0c2e7b92f1c48b43eca535904c6ce0b23e0f53639f8adbc5d93db3f190612499b3236303b56aad5d3ce8356495e16f8062612e46569b360caf207ed5c43331d591b680f0d301adaef041f1b599165bfbf57f8be55020301000102818100d96e5dbbc44179e5e72bc8e49c19f88803458e7715d31f5a77295b6b4506bc647cccd85c8a46349c50186c50750d4582b38a48d6156a92971b21afe40ce5a4eba7b21226aa342bb42374605d07cc6319ea51b8af4276c156c21c9bfedfa77850e38d39296c7b300810d7ac7f1763f8f0e437f8634cda2cf2da50820b21712775024100f22330928418a6345f193a91c2c6d1694b7b8ec3892123913eac46a59c184b16f609d729d5399fbc08e5d331881b35b172551b34f560c0f1ada54d9985f4d5f3024100ef4ac91b8a8bc61c874995d4edb82ee230491d233f417fc113141fd5fa862e6e3cc2c3ddb30e29f5f463c946754ab57bbec700be44e605f097976cdbf1de4497024100de8f35c01626c9eded533520711569ba0ca55f0d9f6794579671a6e5e5d9f67afe5f0123f456e8d95e9c504880bff1d44e30a7b73fab54ed4f1c577d3b4155bd0240501bc53fc71e0bf0b909d573373215dffb323ee2f1e64792a7847133fd6eb654895ada9f79b6202e0ae6ed16fd65496467f5cf35e372ee42213dbc5fd595077902410086ee37e0b0bbe6b2c12c1e2dd4a1841112cf5152f58cc6704300c3903dc2e252ae3f2536e6e1d1e15ba13ec8c6e2dbeea5c876b8fe6a1d01883d09bf618bc63b"

Public_key = "30819f300d06092a864886f70d010101050003818d0030818902818100e25596bc81918822c7287eb3d5446a5456cb45f7f980cecf6c8750b82e7e03f0e523f4156e5ec6f33b2b5be0c2e7b92f1c48b43eca535904c6ce0b23e0f53639f8adbc5d93db3f190612499b3236303b56aad5d3ce8356495e16f8062612e46569b360caf207ed5c43331d591b680f0d301adaef041f1b599165bfbf57f8be550203010001"

Student_Id_Enc_CA_PK = "rAjTdnUBB/DyX4OxWQWKDfTYTsVJV5uAdCcALDsiiff1d4Y29je5ZuaQX7MKf8qVCzsHuVQ4alOLG+vyTUPNZrN9LMabxGWHTxiQmztcub/w+8MH46UkvYOPOstNcUxBdkWmq1PmINGB0P5qB5u/cqvoLVbz85HQv26h5pFHrWZTu3xbx5ZLLsILvIPfRxMV9DCVVyYC8GKIha+xUZ+LicNvYxuZWP23OT1N4b5aqvgNLZ7rTS3D2WSofYcfH+Cmbr/cCwfnTL7+W28C0INp70wqaEK5qknOAMDhnI89M1Eu4/aTaFkraTu6SXwZtcqYcxJcx7ozY9atzK7FI9J20w=="

Hash = "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92"

Digital_signature = "loWJ7Zvcv0Oz0ltcz9CjszmHAZx/tUlpLa8l0BDX11AwQL5uMyeuQTWG/oHzenXtuaYMm+L6CqjdGa4092Ka6Pi57vjWrl9gUSxWSNSupsm11ZcfZuZLWvz8Hfj983f34tDWJKiRB7pC4nY3km4Fnwawv3cD419i/GA7aDBCXBU="
