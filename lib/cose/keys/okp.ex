defmodule COSE.Keys.OKP do
  defstruct [:kty, :kid, :alg, :key_ops, :base_iv, :crv, :x, :d]

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
  def sign(key, digest_type, to_be_signed) do
    :crypto.sign(:eddsa, digest_type, to_be_signed, [key.d, :ed25519])
  end

  def verify(ver_key, digest_type, to_be_verified, signature) do
    :crypto.verify(:eddsa, digest_type, to_be_verified, signature, [ver_key.x, :ed25519])
  end
end
