from eth_typing import BlockNumber

from src.checkpoints.database import CheckpointCrud, CheckpointType


async def test_update_checkpoint_block_number(test_db):
    assert (
        await CheckpointCrud().get_checkpoint_block_number(CheckpointType.SSV_VALIDATOR_ADDED)
        is None
    )

    await CheckpointCrud().update_checkpoint_block_number(
        CheckpointType.SSV_VALIDATOR_ADDED, BlockNumber(5)
    )
    assert (
        await CheckpointCrud().get_checkpoint_block_number(CheckpointType.SSV_VALIDATOR_ADDED) == 5
    )

    await CheckpointCrud().update_checkpoint_block_number(
        CheckpointType.SSV_VALIDATOR_ADDED, BlockNumber(115)
    )
    assert (
        await CheckpointCrud().get_checkpoint_block_number(CheckpointType.SSV_VALIDATOR_ADDED)
        == 115
    )
