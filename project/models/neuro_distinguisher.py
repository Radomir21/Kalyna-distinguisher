from __future__ import annotations

import torch
import torch.nn as nn


class ResidualBlock1D(nn.Module):
    def __init__(self, channels: int, kernel_size: int = 3):
        super().__init__()
        padding = kernel_size // 2

        self.block = nn.Sequential(
            nn.Conv1d(channels, channels, kernel_size=kernel_size, padding=padding),
            nn.BatchNorm1d(channels),
            nn.ReLU(inplace=True),
            nn.Conv1d(channels, channels, kernel_size=kernel_size, padding=padding),
            nn.BatchNorm1d(channels),
            nn.ReLU(inplace=True),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return x + self.block(x)


class AESLikeResNetDistinguisher(nn.Module):
    """
    PyTorch version inspired by the AES repository:

    input shape: (batch, num_blocks * word_size_bits)
    reshape -> (batch, num_blocks, word_size_bits)
    permute -> (batch, word_size_bits, num_blocks)
    Conv1d(1x1) -> residual tower -> flatten -> dense head -> 1 logit
    """

    def __init__(
        self,
        num_blocks: int = 2,
        word_size_bits: int = 16,
        num_filters: int = 16,
        depth: int = 5,
        dense1: int = 64,
        dense2: int = 64,
        kernel_size: int = 3,
    ):
        super().__init__()
        self.num_blocks = num_blocks
        self.word_size_bits = word_size_bits
        self.input_dim = num_blocks * word_size_bits

        self.input_conv = nn.Sequential(
            nn.Conv1d(word_size_bits, num_filters, kernel_size=1, padding=0),
            nn.BatchNorm1d(num_filters),
            nn.ReLU(inplace=True),
        )

        self.res_blocks = nn.Sequential(
            *[ResidualBlock1D(num_filters, kernel_size=kernel_size) for _ in range(depth)]
        )

        self.head = nn.Sequential(
            nn.Flatten(),
            nn.Linear(num_filters * num_blocks, dense1),
            nn.BatchNorm1d(dense1),
            nn.ReLU(inplace=True),
            nn.Linear(dense1, dense2),
            nn.BatchNorm1d(dense2),
            nn.ReLU(inplace=True),
            nn.Linear(dense2, 1),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        batch_size = x.size(0)

        x = x.view(batch_size, self.num_blocks, self.word_size_bits)
        x = x.permute(0, 2, 1)  # (B, word_size_bits, num_blocks)

        x = self.input_conv(x)
        x = self.res_blocks(x)
        x = self.head(x)

        return x.squeeze(-1)