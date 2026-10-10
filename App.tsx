import { useState } from "react";
import { Pressable, Text, View } from "react-native";
import * as Haptics from "expo-haptics";

export default function App() {
  const [count, setCount] = useState(0);
  return (
    <View style={{ flex: 1, alignItems: "center", justifyContent: "center", backgroundColor: "#111", gap: 16 }}>
      <Text style={{ color: "#e8ff47", fontSize: 28, fontWeight: "700" }}>vibe-native</Text>
      <Text style={{ color: "#f5f5f5", fontSize: 18 }}>Native counter {count}</Text>
      <Pressable
        onPress={() => {
          setCount((value) => value + 1);
          void Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Medium).catch(() => undefined);
        }}
        style={{ backgroundColor: "#e8ff47", paddingHorizontal: 22, paddingVertical: 12, borderRadius: 999 }}
      >
        <Text style={{ color: "#111", fontSize: 16, fontWeight: "700" }}>Tap</Text>
      </Pressable>
    </View>
  );
}
