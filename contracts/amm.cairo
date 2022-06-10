from starkware.cairo.common.dict_access import DictAccess
from starkware.cairo.common.dict_access import dict_read
from starkware.cairo.common.dict_access import dict_write
from starkware.cairo.common.dict_access import dict_new
from starkware.cairo.common.math import assert_nn_le
from starkware.cairo.common.math import unsigned_div_rem
from starkware.cairo.common.registers import get_fp_and_pc
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.hash import hash2

struct Account:
    member public_key : felt
    member token_a_balance : felt
    member token_b_balance : felt
end

# Global state of the AMM. Contains token a and token b balances, along with 2 pointers indicating the start and end of the dictionary of accounts.

struct AmmState:
    #A Dictionary that tracks the accounts' state.
    member account_dict_start : DictAccess*
    member account_dict_end : DictAccess*

    member token_a_balance : felt
    member token_b_balance : felt
end

const MAX_BALANCE = 2 ** 64 - 1

func modify_account(state : AmmState, account_id, diff_a, diff_b) -> (state : AmmState, key : felt):
    alloc_locals
    let account_dict_end = state.account_dict_end
    let (local old_account : Account*) = dict_read{dict_ptr=account_dict_end}(key=account_id)

    tempvar new_token_a_balance = old_account.token_a_balance + diff_a
    tempvar new_token_b_balance = old_account.token_b_balance + diff_b

    assert_nn_le(new_token_a_balance, MAX_BALANCE)
    assert_nn_le(new_token_b_balance, MAX_BALANCE)

    local new_account : Account
    new_account.public_key = old_account.public_key
    new_account.token_a_balance = new_token_a_balance
    new_account.token_b_balance = new_token_b_balance

    let (__fp__, _) = get_fp_and_pc()
    dict_write{dict_ptr=account_dict_end}(key=account_id,new_value=cast(&new_account, felt))

    local new_state : AmmState
    assert new_state.account_dict_start = state.account_dict_start
    assert new_state.account_dict_end = state.account_dict_end
    assert new_state.token_a_balance = state.token_a_balance
    assert new_state.token_b_balance = state.token_b_balance
    return (state=new_state, key=old_account.public_key)
end

struct SwapTransaction:
    member account_id : felt
    member token_a_amount : felt
end

func swap(state : AmmState, transaction: SwapTransaction*)->(state: AmmState):
    let account_id = transaction.account_id
    tempvar a = transaction.token_a_amount
    tempvar x = state.token_a_balance #x
    tempvar y = state.token_b_balance #y

    assert_nn_le(a, MAX_BALANCE)

    let (b, _) = unsigned_div_rem(y * a, x + a)

    assert_nn_le(b, MAX_BALANCE)

    #Update balance in account and amm state

    let (state, key) = modify_account(state=state, account_id=account_id, diff_a=-a, diff_b=b)

    tempvar new_x = x + a
    tempvar new_y = y - b

    assert_nn_le(new_x, MAX_BALANCE)
    assert_nn_le(new_y, MAX_BALANCE)

    local new_state : AmmState
    assert new_state.account_dict_start = state.account_dict_start
    assert new_state.account_dict_end = state.account_dict_end
    assert new_state.token_a_balance = new_x
    assert new_state.token_b_balance = new_y

    %{
        # Print the transaction values using a hint, for
        # debugging purposes.
        print(
            f'Swap: Account {ids.transaction.account_id} '
            f'gave {ids.a} tokens of type token_a and '
            f'received {ids.b} tokens of type token_b.')
    %}

    return (state=new_state)
end

func swap_transactions(state : AmmState, transactions : SwapTransaction**, n_steps : felt)->(state : AmmState):
    alloc_locals

    if n_steps == 0:
        return (state=state)
    end

    tempvar transaction : SwapTransaction* = [transactions] #Returns first item in array, which is a pointer to SwapTransaction object

    let (local new_state) = swap(state=state, transaction=transaction)
    swap_transactions(state=new_state, transactions=transactions + 1, n_steps=n_steps - 1)
    return ()
end

func hash_account{pedersen_ptr : HashBuiltin*}(account : Account*)->(result):
    let (result) = hash2{hash_ptr=pedersen_ptr}(account.public_key, account.token_a_balance)
    let (result) = hash2{hash_ptr=pedersen_ptr}(result, account.token_b_balance)
    return (result=result)
end


func hash_dict_values{pedersen_ptr: HashBuiltin*}(dict_start : DictAccess*, dict_end : DictAccess*, hash_dict_start : DictAccess*) -> (hash_dict_end : DictAccess*):
    if dict_start == dict_end:
        return (hash_dict_end=hash_dict_start)
    end
    
    #Compute hash of account before and after the changes
    let (prev_hash) = hash_account(account=cast(dict_start.prev_value, Account*))
    let (new_hash) = hash_account(account=cast(dict_start.new_value, Account*))

    dict_update{dict_ptr=hash_dict_start}(key=dict_start.key, prev_value=prev_hash, new_value=new_hash)
    return hash_dict_values(dict_start=dict_start + DictAccess.SIZE, dict_end=dict_end, hash_dict_start=hash_dict_start)
end

func compute_merkle_roots{pedersen_ptr : HashBuiltin*, range_check_ptr}(state : AmmState) -> (root_before, root_after):
    alloc_locals
    let (squashed_dict_start, squashed_dict_end) = dict_squash(dict_access_start=state.account_dict_start, dict_access_end=state.account_dict_end)
    %{
        from starkware.crypto.signature.signature import pedersen_hash

        initial_dict = {}
        for account_id, account in initial_account_dict.items():
            public_key = memory[account + ids.Account.public_key]
            token_a_balance = memory[account + ids.Account.token_a_balance]
            token_b_balance = memory[account + ids.Account.token_b_balance]
            initial_dict[account_id] = pedersen_hash(pedersen_hash(public_key, token_a_balance), token_b_balance)
    %}
    let (local hash_dict_start : DictAccess* ) = dict_new()
    let (hash_dict_end) = hash_dict_values(dict_start=squashed_dict_start, dict_end=squashed_dict_end, hash_dict_start=hash_dict_start)

    let (root_before, root_after) = small_merkle_tree_update{
        hash_ptr=pedersen_ptr
    }(
        squashed_dict_start=hash_dict_start,
        squashed_dict_end=hash_dict_end,
        height=10
    )

    return (root_before=root_before, root_after=root_after)
end

func get_transactions()->(transactions : SwapTransaction**, n_transactions : felt):
    alloc_locals
    local transactions : SwapTransaction**
    local n_transactions : felt
    %{
        transactions = [
            [
                transaction['account_id'],
                transaction['token_a_amount'],
            ]
            for transaction in program_input['transactions']
        ]
        ids.transactions = segments.gen_arg(transactions)
        ids.n_transactions = len(transactions)
    %}
    return (transactions=transactions, n_transactions=n_transactions)
end

func get_account_dict() -> (account_dict : DictAccess*):
    alloc_locals
    %{
        account = program_input['accounts']
        initial_dict = {
            int(account_id_str): segments.gen_arg([
                int(info['public_key'], 16),
                info['token_a_balance'],
                info['token_b_balance'],
            ])
            for account_id_str, info in account.items()
        }

        # Save a copy initial account dict for
        # compute_merkle_roots.
        initial_account_dict = dict(initial_dict)
    %}

    # Initialize the account dictionary.
    let (account_dict) = dict_new()
    return (account_dict=account_dict)
end

%builtins output pedersen range_check

# The output of the AMM program.
struct AmmBatchOutput:
    # The balances of the AMM before applying the batch.
    member token_a_before : felt
    member token_b_before : felt
    # The balances of the AMM after applying the batch.
    member token_a_after : felt
    member token_b_after : felt
    # The account Merkle roots before and after applying
    # the batch.
    member account_root_before : felt
    member account_root_after : felt
end

func main{
    output_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr,
}():
    alloc_locals

    # Create the initial state.
    local state : AmmState
    %{
        # Initialize the balances using a hint.
        # Later we will output them to the output struct,
        # which will allow the verifier to check that they
        # are indeed valid.
        ids.state.token_a_balance = \
            program_input['token_a_balance']
        ids.state.token_b_balance = \
            program_input['token_b_balance']
    %}

    let (account_dict) = get_account_dict()
    assert state.account_dict_start = account_dict
    assert state.account_dict_end = account_dict

    # Output the AMM's balances before applying the batch.
    let output = cast(output_ptr, AmmBatchOutput*)
    let output_ptr = output_ptr + AmmBatchOutput.SIZE

    assert output.token_a_before = state.token_a_balance
    assert output.token_b_before = state.token_b_balance

    # Execute the transactions.
    let (transactions, n_transactions) = get_transactions()
    let (state : AmmState) = transaction_loop(
        state=state,
        transactions=transactions,
        n_transactions=n_transactions,
    )

    # Output the AMM's balances after applying the batch.
    assert output.token_a_after = state.token_a_balance
    assert output.token_b_after = state.token_b_balance

    # Write the Merkle roots to the output.
    let (root_before, root_after) = compute_merkle_roots(
        state=state
    )
    assert output.account_root_before = root_before
    assert output.account_root_after = root_after

    return ()
end