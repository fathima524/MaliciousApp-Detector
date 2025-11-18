import React, { useState } from 'react';
import {
  View,
  Text,
  TouchableOpacity,
  StyleSheet,
  SafeAreaView,
  ActivityIndicator,
  ScrollView,
  Alert,
} from 'react-native';
import * as DocumentPicker from 'expo-document-picker';

// ✅ Use 10.0.2.2 for emulator, OR 127.0.0.1 if using adb reverse
const API_URL = "https://premises-advocacy-substances-differences.trycloudflare.com/analyze_full/";




function ScanStatusLog({ staticLog, dynamicLog }) {
  return (
    <View style={[styles.card, { maxHeight: 200 }]}>
      <ScrollView>
        <Text style={styles.resultTitle}>Static Analysis Logs:</Text>
        {staticLog.length === 0 ? (
          <Text style={styles.resultText}>No static logs available</Text>
        ) : (
          staticLog.map((msg, i) => (
            <Text key={`staticlog-${i}`} style={styles.logText}>{msg}</Text>
          ))
        )}

        <Text style={[styles.resultTitle, { marginTop: 12 }]}>Dynamic Analysis Logs:</Text>
        {dynamicLog.length === 0 ? (
          <Text style={styles.resultText}>No dynamic logs available</Text>
        ) : (
          dynamicLog.map((msg, i) => (
            <Text key={`dynamiclog-${i}`} style={styles.logText}>{msg}</Text>
          ))
        )}
      </ScrollView>
    </View>
  );
}

export default function App() {
  const [selectedFile, setSelectedFile] = useState(null);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [uploading, setUploading] = useState(false);

  const pickFile = async () => {
    try {
      const result = await DocumentPicker.getDocumentAsync({ type: "*/*" });
      console.log("Picked file:", result);

      if (!result.canceled && result.assets?.length > 0) {
        const file = result.assets[0];
        if (file.name.endsWith(".apk")) {
          setSelectedFile(file);
          setAnalysisResult(null);
        } else {
          Alert.alert("Invalid File", "Please select an APK file.");
        }
      }
    } catch (err) {
      console.error("File pick error:", err);
    }
  };

  const uploadAndAnalyze = async () => {
    if (!selectedFile) return;

    setUploading(true);
    try {
      const formData = new FormData();
      formData.append("file", {
        uri: selectedFile.uri,
        name: selectedFile.name,
        type: "application/vnd.android.package-archive",
      });

      const response = await fetch(API_URL, {
        method: "POST",
        body: formData,
        headers: {
          // DO NOT manually set multipart boundary — fetch handles it
        },
      });

      if (!response.ok) {
        throw new Error(`Server returned ${response.status}`);
      }

      const result = await response.json();
      console.log("Server response:", result);
      setAnalysisResult(result);
    } catch (err) {
      console.error("Upload error:", err);
      Alert.alert("Error", "Failed to analyze file: " + err.message);
    } finally {
      setUploading(false);
    }
  };

  return (
    <SafeAreaView style={styles.container}>
      <ScrollView>
        <Text style={styles.header}>Home</Text>

        <View style={styles.card}>
          <Text style={styles.title}>SecureApp</Text>
          <Text style={styles.label}>Security Status</Text>
          <View style={styles.statusRow}>
            <View style={styles.statusIcon} />
            <View>
              <Text style={styles.statusText}>System Secure</Text>
              <Text style={styles.statusSub}>Ready to scan APKs</Text>
            </View>
          </View>
        </View>

        <Text style={styles.section}>Quick Actions</Text>
        <View style={styles.card}>
          <TouchableOpacity style={styles.actionBtn} onPress={pickFile}>
            <Text style={styles.actionTitle}>Scan APK File</Text>
            <Text style={styles.actionDesc}>Upload & analyze suspicious apps</Text>
          </TouchableOpacity>

          <Text style={styles.selectedFile}>
            {selectedFile ? `Selected: ${selectedFile.name}` : "No APK selected"}
          </Text>

          <TouchableOpacity
            style={[
              styles.scanBtn,
              { backgroundColor: selectedFile && !uploading ? "#2639f8" : "#666" },
            ]}
            disabled={!selectedFile || uploading}
            onPress={uploadAndAnalyze}
          >
            {uploading ? (
              <ActivityIndicator color="#fff" />
            ) : (
              <Text style={styles.scanBtnText}>Start Analysis</Text>
            )}
          </TouchableOpacity>
        </View>

        {analysisResult && (
          <>
            <View style={styles.card}>
              <Text style={styles.resultTitle}>Scan Result:</Text>
              <Text style={styles.resultText}>
                {`Status:\nStatic Analysis: ${analysisResult.static_status}\nDynamic Analysis: ${analysisResult.dynamic_status}\nClassification: ${analysisResult.classification}\nMalicious Probability: ${(analysisResult.malicious_probability * 100).toFixed(1)}%`}
              </Text>
            </View>

            <ScanStatusLog
              staticLog={analysisResult.static_stage_log || []}
              dynamicLog={analysisResult.dynamic_stage_log || []}
            />
          </>
        )}

        <Text style={styles.section}>Analysis Info</Text>
        <View style={styles.infoRow}>
          <View style={styles.infoBox}>
            <Text style={styles.infoValue}>3-5</Text>
            <Text style={styles.infoLabel}>Minutes</Text>
          </View>
          <View style={styles.infoBox}>
            <Text style={styles.infoValue}>99%</Text>
            <Text style={styles.infoLabel}>Accuracy</Text>
          </View>
          <View style={styles.infoBox}>
            <Text style={styles.infoValue}>Safe</Text>
            <Text style={styles.infoLabel}>Process</Text>
          </View>
        </View>
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: "#181818" },
  header: { fontSize: 20, color: "#fff", margin: 20, fontWeight: "bold" },
  card: { backgroundColor: "#232323", borderRadius: 20, padding: 18, margin: 18, marginTop: 0 },
  title: { fontSize: 24, color: "#fff", fontWeight: "bold", marginBottom: 14 },
  label: { color: "#eee", marginBottom: 10, fontWeight: "600", fontSize: 16 },
  statusRow: { flexDirection: "row", alignItems: "center", marginBottom: 2 },
  statusIcon: { width: 32, height: 32, borderRadius: 16, backgroundColor: "#59d878", marginRight: 10 },
  statusText: { color: "#fff", fontWeight: "bold", fontSize: 16 },
  statusSub: { color: "#aaa", fontSize: 13 },
  section: { color: "#fff", marginLeft: 22, marginTop: 18, marginBottom: 6, fontSize: 15, fontWeight: "bold" },
  actionBtn: { backgroundColor: "#2639f8", borderRadius: 14, padding: 15, marginBottom: 8 },
  actionTitle: { color: "#fff", fontSize: 18, fontWeight: "bold" },
  actionDesc: { color: "#e0e0e0", fontSize: 13 },
  selectedFile: { color: "#fff", fontSize: 14, marginBottom: 8 },
  scanBtn: { paddingVertical: 16, borderRadius: 11, marginBottom: 4, alignItems: "center" },
  scanBtnText: { color: "#fff", fontSize: 16, fontWeight: "bold" },
  resultTitle: { color: "#59d878", fontWeight: "bold", fontSize: 16, marginBottom: 9 },
  resultText: { color: "#fff", fontSize: 13 },
  infoRow: { flexDirection: "row", justifyContent: "space-evenly", marginTop: 8, marginBottom: 24 },
  infoBox: { backgroundColor: "#222", padding: 10, borderRadius: 10, alignItems: "center", minWidth: 80 },
  infoValue: { color: "#fff", fontWeight: "bold", fontSize: 18 },
  infoLabel: { color: "#ccc", fontSize: 13 },
  logText: {
    color: '#ccc',
    fontFamily: 'monospace',
    marginBottom: 3,
  }
});
