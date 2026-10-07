import os
import time
import math
import numpy as np
import cv2
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader

class ResidualPatchCNN(nn.Module):
    """
    Lightweight, CPU-friendly 128x128 residual patch classifier.
    Directly extracts Laplacian, High-pass, FFT, and Wavelet residuals
    and passes them to a lightweight CNN.
    """
    def __init__(self):
        super(ResidualPatchCNN, self).__init__()
        # Input has 4 channels representing the 4 residual modalities:
        # Channel 0: Laplacian
        # Channel 1: High-pass residual
        # Channel 2: FFT high-freq residual
        # Channel 3: Wavelet detail subband (HH)
        self.conv1 = nn.Conv2d(4, 16, kernel_size=3, padding=1)
        self.relu1 = nn.ReLU()
        self.pool1 = nn.MaxPool2d(2, 2) # 64x64
        
        # Residual block 1
        self.conv2 = nn.Conv2d(16, 16, kernel_size=3, padding=1)
        self.relu2 = nn.ReLU()
        
        # Conv block 2
        self.conv3 = nn.Conv2d(16, 32, kernel_size=3, padding=1)
        self.relu3 = nn.ReLU()
        self.pool2 = nn.MaxPool2d(2, 2) # 32x32
        
        # Residual block 2
        self.conv4 = nn.Conv2d(32, 32, kernel_size=3, padding=1)
        self.relu4 = nn.ReLU()
        
        # Classification layers
        self.gap = nn.AdaptiveAvgPool2d(1) # 1x1
        self.fc = nn.Linear(32, 1)
        self.sigmoid = nn.Sigmoid()
        
    def forward(self, x):
        # x shape: (B, 4, 128, 128)
        out = self.relu1(self.conv1(x))
        res1 = out
        out = self.relu2(self.conv2(out)) + res1
        out = self.pool1(out)
        
        out = self.relu3(self.conv3(out))
        res2 = out
        out = self.relu4(self.conv4(out)) + res2
        out = self.pool2(out)
        
        out = self.gap(out)
        out = out.view(out.size(0), -1)
        out = self.fc(out)
        out = self.sigmoid(out)
        return out

def preprocess_patch(patch_bgr: np.ndarray) -> np.ndarray:
    """
    Computes the 4 residual channels for a 128x128 BGR patch:
    1. Laplacian
    2. High-pass (Gaussian difference)
    3. FFT high frequency magnitude
    4. Wavelet details (HH subband)
    """
    gray = cv2.cvtColor(patch_bgr, cv2.COLOR_BGR2GRAY).astype(np.float32)
    
    # 1. Laplacian
    laplacian = cv2.Laplacian(gray, cv2.CV_32F)
    
    # 2. High-pass filter
    blurred = cv2.GaussianBlur(gray, (5, 5), 0)
    hp_residual = gray - blurred
    
    # 3. FFT high frequency
    dft = np.fft.fft2(gray)
    dft_shift = np.fft.fftshift(dft)
    magnitude = np.abs(dft_shift)
    h, w = magnitude.shape
    cy, cx = h // 2, w // 2
    fft_high = magnitude.copy()
    cv2.circle(fft_high, (cx, cy), min(h, w) // 4, 0, -1)
    
    # 4. Wavelet HH (Haar)
    a = (gray[:, 0::2] + gray[:, 1::2]) / 2.0
    d = (gray[:, 0::2] - gray[:, 1::2]) / 2.0
    HH = (d[0::2, :] - d[1::2, :]) / 2.0
    HH_resized = cv2.resize(HH, (128, 128))
    
    # Normalize channels to zero-mean unit-variance
    def norm(img):
        std = np.std(img)
        if std < 1e-5:
            return img - np.mean(img)
        return (img - np.mean(img)) / std
        
    ch0 = norm(laplacian)
    ch1 = norm(hp_residual)
    ch2 = norm(fft_high)
    ch3 = norm(HH_resized)
    
    return np.stack([ch0, ch1, ch2, ch3], axis=0) # shape (4, 128, 128)

class PatchDataset(Dataset):
    def __init__(self, real_patches: list, fake_patches: list):
        self.patches = real_patches + fake_patches
        self.labels = [0.0] * len(real_patches) + [1.0] * len(fake_patches)
        
    def __len__(self):
        return len(self.patches)
        
    def __getitem__(self, idx):
        patch = self.patches[idx]
        label = self.labels[idx]
        
        # Preprocess patch to 4-channel tensor
        processed = preprocess_patch(patch)
        return torch.tensor(processed, dtype=torch.float32), torch.tensor([label], dtype=torch.float32)

def train_model(real_dir: str, fake_dir: str, output_path: str = "models/patch_cnn.pth", epochs: int = 10, batch_size: int = 16):
    print(f"Starting patch CNN training pipeline...")
    
    # Load raw patches (128x128)
    real_patches = []
    fake_patches = []
    
    # Load real images and extract patches
    if os.path.exists(real_dir):
        for f in os.listdir(real_dir):
            if f.lower().endswith(('.png', '.jpg', '.jpeg')):
                img = cv2.imread(os.path.join(real_dir, f))
                if img is not None:
                    h, w = img.shape[:2]
                    # Extract 128x128 patches
                    for y in range(0, h - 128 + 1, 64):
                        for x in range(0, w - 128 + 1, 64):
                            real_patches.append(img[y:y+128, x:x+128])
                            if len(real_patches) >= 200: # Limit for demo/smoke test
                                break
                        if len(real_patches) >= 200:
                            break
    
    # Load fake images and extract patches
    if os.path.exists(fake_dir):
        for f in os.listdir(fake_dir):
            if f.lower().endswith(('.png', '.jpg', '.jpeg')):
                img = cv2.imread(os.path.join(fake_dir, f))
                if img is not None:
                    h, w = img.shape[:2]
                    for y in range(0, h - 128 + 1, 64):
                        for x in range(0, w - 128 + 1, 64):
                            fake_patches.append(img[y:y+128, x:x+128])
                            if len(fake_patches) >= 200:
                                break
                        if len(fake_patches) >= 200:
                            break

    # If no data found, generate dummy patches for testing/compilation verification
    if not real_patches or not fake_patches:
        print("Warning: Real or fake data directory not found or empty. Generating dummy dataset for pipeline verification.")
        for _ in range(50):
            # Real-like patches: smoother gradients
            p_real = np.zeros((128, 128, 3), dtype=np.uint8)
            cv2.circle(p_real, (64, 64), 30, (120, 150, 180), -1)
            p_real = cv2.GaussianBlur(p_real, (5, 5), 0)
            real_patches.append(p_real)
            
            # Fake-like patches: high-frequency noise and checkboard pattern
            p_fake = np.random.randint(0, 255, (128, 128, 3), dtype=np.uint8)
            fake_patches.append(p_fake)
            
    dataset = PatchDataset(real_patches, fake_patches)
    dataloader = DataLoader(dataset, batch_size=batch_size, shuffle=True)
    
    device = torch.device("cpu") # Keep CPU friendly
    model = ResidualPatchCNN().to(device)
    criterion = nn.BCELoss()
    optimizer = optim.Adam(model.parameters(), lr=0.001)
    
    print(f"Dataset loaded. Total patches: {len(dataset)} (Real: {len(real_patches)}, Fake: {len(fake_patches)})")
    print(f"Training on device: {device}")
    
    model.train()
    for epoch in range(epochs):
        epoch_loss = 0.0
        correct = 0
        total = 0
        for inputs, targets in dataloader:
            inputs, targets = inputs.to(device), targets.to(device)
            
            optimizer.zero_grad()
            outputs = model(inputs)
            loss = criterion(outputs, targets)
            loss.backward()
            optimizer.step()
            
            epoch_loss += loss.item() * inputs.size(0)
            predictions = (outputs >= 0.5).float()
            correct += (predictions == targets).sum().item()
            total += targets.size(0)
            
        avg_loss = epoch_loss / total
        accuracy = correct / total
        print(f"Epoch {epoch+1}/{epochs} - Loss: {avg_loss:.4f} - Accuracy: {accuracy:.4f}")
        
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    torch.save(model.state_dict(), output_path)
    print(f"Model saved successfully to {output_path}!")

if __name__ == "__main__":
    # Example usage
    train_model(real_dir="data/train/real", fake_dir="data/train/fake", output_path="models/patch_cnn.pth", epochs=3, batch_size=8)
