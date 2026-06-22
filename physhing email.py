import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
import seaborn as sns
import matplotlib.pyplot as plt

# Sample dataset
data = {
    'email': [
        "Congratulations! You have won $1000. Click here to claim now.",
        "Urgent! Verify your bank account immediately.",
        "Meeting scheduled for tomorrow at 10 AM.",
        "Please find the attached project report.",
        "Your account has been suspended. Login immediately.",
        "Happy Birthday! Have a wonderful day.",
        "Win a free iPhone now. Limited offer!",
        "Let's have lunch together tomorrow."
    ],
    'label': [
        'Phishing',
        'Phishing',
        'Safe',
        'Safe',
        'Phishing',
        'Safe',
        'Phishing',
        'Safe'
    ]
}

# Create DataFrame
df = pd.DataFrame(data)

# Features and target
X = df['email']
y = df['label']

# Convert text into numerical features
vectorizer = TfidfVectorizer(stop_words='english')
X_vectorized = vectorizer.fit_transform(X)

# Split data
X_train, X_test, y_train, y_test = train_test_split(
    X_vectorized, y, test_size=0.3, random_state=42
)

# Train model
model = MultinomialNB()
model.fit(X_train, y_train)

# Prediction
y_pred = model.predict(X_test)

# Accuracy
accuracy = accuracy_score(y_test, y_pred)
print("Accuracy:", accuracy)

# Classification report
print("\nClassification Report:")
print(classification_report(y_test, y_pred))

# Confusion matrix
cm = confusion_matrix(y_test, y_pred)

plt.figure(figsize=(5,4))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=['Phishing', 'Safe'],
            yticklabels=['Phishing', 'Safe'])
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.title("Confusion Matrix")
plt.show()

# Test custom email
while True:
    email = input("\nEnter an email message (or type exit): ")

    if email.lower() == "exit":
        break

    email_vector = vectorizer.transform([email])
    prediction = model.predict(email_vector)

    print("Prediction:", prediction[0])