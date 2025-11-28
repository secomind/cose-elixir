defprotocol COSE.Keys.Key do
  def sign(key, digest_type, to_be_signed)
  def verify(key, digest_type, to_be_verified, signature)
end

defmodule COSE.Keys do
  alias COSE.Keys.ECC
  alias COSE.Keys.Key
  alias COSE.Keys.RSA

  @oid_rsa {1, 2, 840, 113_549, 1, 1, 1}
  @oid_ec {1, 2, 840, 10045, 2, 1}

  def sign(key, digest_type, to_be_signed), do: Key.sign(key, digest_type, to_be_signed)

  def verify(key, digest_type, to_be_verified, signature),
    do: Key.verify(key, digest_type, to_be_verified, signature)

  def from_pem(pem, password \\ "") do
    pem
    |> :public_key.pem_decode()
    |> Enum.find_value(:error, fn pem_entry -> safe_decode(pem_entry, password) end)
  end

  defp safe_decode(pem_entry, password) do
    try do
      :public_key.pem_entry_decode(pem_entry, password)
      |> from_record()
    rescue
      _e -> false
    end
  end

  defp from_record(pem_record) do
    case pem_record do
      {:RSAPrivateKey, _, _, _, _, _, _, _, _, _, _} ->
        {:ok, RSA.from_record(pem_record)}

      {:PrivateKeyInfo, _, {_, @oid_rsa, _}, _, _} ->
        record = :public_key.der_decode(:RSAPrivateKey, pem_record)
        {:ok, RSA.from_record(record)}

      {:ECPrivateKey, _, _, _, _, _} ->
        {:ok, ECC.from_record(pem_record)}

      {:PrivateKeyInfo, _, {_, @oid_ec, _}, _, _} ->
        {:ok, ECC.from_record(pem_record)}

      _ ->
        false
    end
  end
end
