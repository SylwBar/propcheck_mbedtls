defmodule PCMbedTLS do
  use PropCheck.StateM
  @trace false
  @psa_its_storage "/tmp/"

  defp command_list(),
    do: [
      PSACryptoInit,
      PSAKeyAttributesInit,
      PSAResetKeyAttributes,
      PSAGetKeyAttributes,
      PSASetKeyId,
      PSAGetKeyId,
      PSASetKeyType,
      PSASetKeyBits,
      PSASetKeyAlgorithm,
      PSASetKeyUsageFlags,
      PSAGenerateRandom.Success,
      PSAGenerateRandom.Fail,
      PSAGenerateKey.Volatile.Success,
      PSAGenerateKey.Persistent.Success,
      PSAGenerateKey.Persistent.PSA_ERROR_ALREADY_EXISTS,
      PSAImportKey.Volatile.Success,
      PSACopyKey.Volatile.Success,
      PSACopyKey.Persistent.Success,
      PowerCycle
    ]

  defp prep_command(cmd_module, state) do
    cmd_weight =
      if :erlang.function_exported(cmd_module, :weight, 0) do
        :erlang.apply(cmd_module, :weight, [])
      else
        1
      end

    {cmd_weight, {:call, cmd_module, :exec, cmd_module.args(state)}}
  end

  defp filter_command(cmd_module, state) do
    if :erlang.function_exported(cmd_module, :pre, 1) do
      :erlang.apply(cmd_module, :pre, [state])
    else
      true
    end
  end

  defp prep_commands(commands, state) do
    filtered_commands = Enum.filter(commands, &filter_command(&1, state))
    frequency(Enum.map(filtered_commands, &prep_command(&1, state)))
  end

  # ------ PropCheck.StateM command callback ------
  def command(state), do: command_list() |> prep_commands(state)

  # ------ PropCheck.StateM precondition callback ------
  def precondition(state, {:call, mod, _fun, args}) do
    if :erlang.function_exported(mod, :pre, 2) do
      :erlang.apply(mod, :pre, [state, args])
    else
      true
    end
  end

  # ------ PropCheck.StateM postcondition callback ------
  def postcondition(state, {:call, mod, _fun, args}, res) do
    if @trace and :erlang.function_exported(mod, :trace, 3) do
      :erlang.apply(mod, :trace, [state, args, res])
    end

    if :erlang.function_exported(mod, :post, 3) do
      :erlang.apply(mod, :post, [state, args, res])
    else
      true
    end
  end

  # ------ PropCheck.StateM next_state callback ------

  def next_state(state, res, {:call, mod, _fun, args}) do
    :erlang.apply(mod, :next, [state, args, res])
  end

  # ------ PropCheck.StateM initial_state callback ------

  def initial_state() do
    MbedTLS.mbedtls_psa_crypto_free()
    State.initial_state()
  end

  def clean_storage() do
    command = "rm -f " <> @psa_its_storage <> "*.psa_its"
    command |> to_charlist |> :os.cmd()
  end

  defp cleanup(state) do
    MbedTLS.mbedtls_psa_crypto_free()
    if state.key_attributes_ptr != nil, do: MbedTLS.free(state.key_attributes_ptr)
    clean_storage()
  end

  def property() do
    forall cmds <- commands(PCMbedTLS) do
      if @trace, do: IO.puts("--------- Test ---------")
      {_history, state, result} = run_commands(PCMbedTLS, cmds)
      cleanup(state)

      (result == :ok)
      |> aggregate(command_names(cmds))
    end
  end

  def start(numtests \\ 100) do
    :ok = :code.ensure_modules_loaded(command_list())
    clean_storage()
    quickcheck(property(), [:noshrink, numtests: numtests])
  end

  def check(example) do
    check(property(), example)
  end
end
