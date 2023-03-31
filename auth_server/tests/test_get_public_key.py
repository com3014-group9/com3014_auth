# Test getting the public key
def test_get_public_key(client, public_key):    
    response = client.post("/auth/get-public-key")
    assert response.json["public_key"] == public_key