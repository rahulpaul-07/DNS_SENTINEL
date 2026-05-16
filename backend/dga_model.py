import torch
import torch.nn as nn
import torch.nn.functional as F
import string
import os

# Device configuration
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

class DGAModel(nn.Module):
    def __init__(self, vocab_size=100, embed_dim=64, cnn_channels=64, lstm_hidden=64, lstm_layers=1, dropout=0.2):
        super(DGAModel, self).__init__()
        
        # Character Embedding
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        
        # Lean 1D CNN
        self.conv3 = nn.Conv1d(embed_dim, cnn_channels, kernel_size=3, padding=1)
        self.conv5 = nn.Conv1d(embed_dim, cnn_channels, kernel_size=5, padding=2)
        
        # BiLSTM
        self.lstm = nn.LSTM(cnn_channels * 2, lstm_hidden, num_layers=lstm_layers, 
                            batch_first=True, bidirectional=True)
        
        # Dense layer with "Length Injection" (LSTM Out + 1 for length)
        self.fc = nn.Linear(lstm_hidden * 2 + 1, 1)
        
        self.temperature = nn.Parameter(torch.ones(1))
        
        # Xavier Initialization for better starting gradients
        for name, param in self.named_parameters():
            if 'weight' in name and len(param.shape) > 1:
                nn.init.xavier_uniform_(param)

    def forward(self, x, length):
        # x shape: (batch_size, seq_len), length shape: (batch_size, 1)
        x = self.embedding(x) 
        x = x.transpose(1, 2) 
        
        c3 = F.relu(self.conv3(x))
        c5 = F.relu(self.conv5(x))
        
        x = torch.cat((c3, c5), dim=1) 
        x = x.transpose(1, 2)
        
        lstm_out, _ = self.lstm(x) 
        out = lstm_out[:, -1, :] 
        
        # Inject domain length feature directly into the final layer
        combined = torch.cat((out, length), dim=1)
        
        logits = self.fc(combined) / self.temperature
        return logits

# Character Mapping (Optimized for DNS domains)
CHARS = "abcdefghijklmnopqrstuvwxyz0123456789.-"
CHAR_TO_IDX = {char: i + 1 for i, char in enumerate(CHARS)}
VOCAB_SIZE = len(CHARS) + 1 # +1 for padding index 0
MAX_LEN = 64

def preprocess_domain(domain: str):
    """Converts domain string to tensor of indices."""
    domain = domain.lower() # Case-insensitive
    indices = [CHAR_TO_IDX.get(c, 0) for c in domain[:MAX_LEN]]
    # Pad or truncate
    if len(indices) < MAX_LEN:
        indices += [0] * (MAX_LEN - len(indices))
    return torch.tensor(indices, dtype=torch.long).unsqueeze(0).to(device)

# Global model instance for inference
_model_instance = None

def get_model():
    global _model_instance
    if _model_instance is None:
        model_path = os.path.join(os.path.dirname(__file__), "dga_model.pt")
        _model_instance = DGAModel(vocab_size=VOCAB_SIZE).to(device)
        if os.path.exists(model_path):
            try:
                _model_instance.load_state_dict(torch.load(model_path, map_location=device))
            except Exception as e:
                print(f"[!] Error loading DGA model: {e}")
        _model_instance.eval()
    return _model_instance

def predict(domain: str) -> float:
    """
    Synchronous prediction for a single domain.
    Optimized for <2ms CPU latency.
    """
    model = get_model()
    with torch.no_grad():
        input_tensor = preprocess_domain(domain)
        length_tensor = torch.tensor([[len(domain)]], dtype=torch.float).to(device)
        logits = model(input_tensor, length_tensor)
        score = torch.sigmoid(logits).item()
    return score
