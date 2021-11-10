defmodule PCMbedTLSTest do
  use ExUnit.Case
  doctest PCMbedTLS

  test "greets the world" do
    assert PCMbedTLS.hello() == :world
  end
end
