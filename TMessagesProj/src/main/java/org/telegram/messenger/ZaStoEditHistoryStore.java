package org.telegram.messenger;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONArray;
import org.json.JSONObject;
import org.telegram.tgnet.TLRPC;

import java.util.ArrayList;
import java.util.List;

/**
 * Persists previous versions of remotely-edited messages (ZaSto edit history).
 *
 * Per-account SharedPreferences file, keyed by the real (dialogId + mid) pair so channel and
 * regular message-id spaces can never collide. Value = a JSON array (oldest-first) of
 * {@code {"d": <unix seconds>, "t": <previous text/caption>}}. Text is primary; pure media or
 * markup edits (text unchanged) are not recorded. Mirrors the {@link ZaStoDeletedStore} pattern —
 * no DB schema change, revert by flipping {@link ZaStoPrivacy#KEEP_EDIT_HISTORY}.
 */
public final class ZaStoEditHistoryStore {

    private static final int MAX_VERSIONS = 50;

    private static SharedPreferences prefs(int account) {
        return ApplicationLoader.applicationContext.getSharedPreferences("zasto_edits_" + account, Context.MODE_PRIVATE);
    }

    private static String key(long dialogId, int mid) {
        return "h" + dialogId + "_" + mid;
    }

    /** Record oldMessage's text as a prior version of the edited message, if the text actually changed. */
    public static synchronized void recordEdit(int account, long dialogId, TLRPC.Message oldMessage, TLRPC.Message newMessage) {
        if (oldMessage == null || newMessage == null) {
            return;
        }
        String prev = oldMessage.message == null ? "" : oldMessage.message;
        String next = newMessage.message == null ? "" : newMessage.message;
        if (prev.equals(next)) {
            return; // text/caption unchanged → nothing to keep (covers pure media / reaction / markup edits)
        }
        try {
            SharedPreferences p = prefs(account);
            String k = key(dialogId, newMessage.id);
            String existing = p.getString(k, null);
            JSONArray array = existing != null ? new JSONArray(existing) : new JSONArray();
            if (array.length() > 0) {
                JSONObject last = array.optJSONObject(array.length() - 1);
                if (last != null && prev.equals(last.optString("t"))) {
                    return; // dedupe a re-delivered identical edit
                }
            }
            int d = oldMessage.edit_date != 0 ? oldMessage.edit_date : oldMessage.date;
            array.put(new JSONObject().put("d", d).put("t", prev));
            while (array.length() > MAX_VERSIONS) {
                array.remove(0);
            }
            p.edit().putString(k, array.toString()).apply();
        } catch (Exception ignore) {
        }
    }

    public static boolean has(int account, long dialogId, int mid) {
        return prefs(account).contains(key(dialogId, mid));
    }

    /** Prior versions, oldest first (empty if none). */
    public static List<Version> get(int account, long dialogId, int mid) {
        List<Version> out = new ArrayList<>();
        try {
            String s = prefs(account).getString(key(dialogId, mid), null);
            if (s != null) {
                JSONArray array = new JSONArray(s);
                for (int i = 0; i < array.length(); i++) {
                    JSONObject o = array.optJSONObject(i);
                    if (o != null) {
                        out.add(new Version(o.optInt("d"), o.optString("t")));
                    }
                }
            }
        } catch (Exception ignore) {
        }
        return out;
    }

    public static final class Version {
        public final int date;
        public final String text;

        Version(int date, String text) {
            this.date = date;
            this.text = text;
        }
    }

    private ZaStoEditHistoryStore() {
    }
}
