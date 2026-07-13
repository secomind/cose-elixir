defmodule COSE.Keys.OKP do
  @moduledoc """
  COSE OKP (Octet Key Pair) key type.

  COSE integer labels follow RFC 9052. After a CBOR round-trip, atom values
  (`:okp`, `:x25519`) come back as binary strings (`"okp"`, `"x25519"`).
  """

  defstruct [:kty, :kid, :alg, :key_ops, :base_iv, :crv, :x, :d]

  @crv_enum Ecto.ParameterizedType.init(Ecto.Enum, values: [x25519: 4, ed25519: 6])

  # COSE Key common parameter labels (RFC 9052 §7.1)
  @kty 1
  @crv -1

  # COSE Key type value: OKP = 1
  @kty_okp 1

  # COSE OKP key parameter: public key x coordinate
  @x -2

  # Expected byte length of an X25519 public key (RFC 7748 §6.1)
  @x25519_key_size 32

  @doc """
  Parses a decoded COSE_Key map into a typed COSE key struct.

  Dispatches on `kty` and `crv`. Each clause embeds the key-size
  validation for that specific algorithm
  """
  @spec decode(map()) :: {:ok, %__MODULE__{}} | {:error, :invalid_cose_key}
  def decode(%{@kty => @kty_okp, @crv => crv_int, @x => x_in}) do
    with {:ok, crv_atom} <- Ecto.Type.load(@crv_enum, crv_int),
         {:ok, x} <- unwrap_bytes(x_in),
         true <- byte_size(x) == @x25519_key_size do
      {:ok, %__MODULE__{kty: :okp, crv: crv_atom, x: x}}
    else
      _ -> {:error, :invalid_cose_key}
    end
  end

  def decode(_), do: {:error, :invalid_cose_key}

  defp unwrap_bytes(%CBOR.Tag{tag: :bytes, value: bin}) when is_binary(bin), do: {:ok, bin}
  defp unwrap_bytes(bin) when is_binary(bin), do: {:ok, bin}
  defp unwrap_bytes(_), do: :error

  def generate(:enc) do
    {x, d} = :crypto.generate_key(:eddh, :x25519)

    %__MODULE__{
      kty: :okp,
      crv: :x25519,
      x: x,
      d: d
    }
  end

  def generate(:sig) do
    {x, d} = :crypto.generate_key(:eddsa, :ed25519)

    %__MODULE__{
      kty: :okp,
      crv: :ed25519,
      x: x,
      d: d
    }
  end
end

defimpl COSE.Keys.Key, for: COSE.Keys.OKP do
  @kty 1
  @crv -1
  @x -2

  @crv_enum Ecto.ParameterizedType.init(Ecto.Enum, values: [x25519: 4, ed25519: 6])

  def sign(key, digest_type, to_be_signed) do
    signature = :crypto.sign(:eddsa, digest_type, to_be_signed, [key.d, :ed25519])
    {:ok, signature}
  end

  def verify(ver_key, digest_type, to_be_verified, signature) do
    case :crypto.verify(:eddsa, digest_type, to_be_verified, signature, [ver_key.x, :ed25519]) do
      true -> :ok
      false -> {:error, :invalid_signature}
    end
  end

  def encode(key),
    do: %{@kty => 1, @crv => encode_crv(key.crv), @x => key.x}

  defp encode_crv(crv) do
    {:ok, int} = Ecto.Type.dump(@crv_enum, crv)
    int
  end
end
