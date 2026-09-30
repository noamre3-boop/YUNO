-- YUNO account upgrade. Run setup-private-upgrade.sql first if the tables do not exist.
-- Back up the database. Existing display names must be unique (case-insensitively).
BEGIN;
CREATE SCHEMA IF NOT EXISTS private;
CREATE SCHEMA IF NOT EXISTS extensions;
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA extensions;
CREATE TABLE IF NOT EXISTS private.yuno_account_secrets(account_id uuid PRIMARY KEY REFERENCES public.yuno_profiles(user_id) ON DELETE CASCADE,pin_hash text NOT NULL,phone text NOT NULL DEFAULT '',failures integer NOT NULL DEFAULT 0,locked_until timestamptz);
CREATE TABLE IF NOT EXISTS private.yuno_sessions(session_uid uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,account_id uuid NOT NULL REFERENCES public.yuno_profiles(user_id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS private.yuno_admins(account_id uuid PRIMARY KEY REFERENCES public.yuno_profiles(user_id) ON DELETE CASCADE);
REVOKE ALL ON SCHEMA private FROM PUBLIC,anon,authenticated;
REVOKE ALL ON ALL TABLES IN SCHEMA private FROM PUBLIC,anon,authenticated;
GRANT USAGE ON SCHEMA private TO authenticated;
CREATE UNIQUE INDEX IF NOT EXISTS yuno_profiles_unique_name ON public.yuno_profiles(lower(btrim(display_name)));
CREATE OR REPLACE FUNCTION private.yuno_account_id() RETURNS uuid LANGUAGE sql STABLE SECURITY DEFINER SET search_path='' AS $$ SELECT account_id FROM private.yuno_sessions WHERE session_uid=auth.uid() $$;
CREATE OR REPLACE FUNCTION private.yuno_is_admin() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path='' AS $$ SELECT EXISTS(SELECT 1 FROM private.yuno_admins WHERE account_id=private.yuno_account_id()) $$;
REVOKE ALL ON FUNCTION private.yuno_account_id(),private.yuno_is_admin() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.yuno_account_id(),private.yuno_is_admin() TO authenticated;
DO $$ DECLARE p record; BEGIN FOR p IN SELECT schemaname,tablename,policyname FROM pg_policies WHERE schemaname='public' AND tablename IN ('yuno_items','yuno_profiles','yuno_messages') LOOP EXECUTE format('DROP POLICY %I ON %I.%I',p.policyname,p.schemaname,p.tablename); END LOOP; END $$;
REVOKE ALL ON public.yuno_items,public.yuno_profiles,public.yuno_messages FROM anon;
GRANT SELECT,INSERT,UPDATE,DELETE ON public.yuno_items TO authenticated;
GRANT SELECT,UPDATE ON public.yuno_profiles TO authenticated;
REVOKE INSERT,DELETE ON public.yuno_profiles FROM authenticated;
GRANT SELECT,INSERT,DELETE ON public.yuno_messages TO authenticated;
REVOKE UPDATE ON public.yuno_messages FROM authenticated;
CREATE POLICY yuno_items_read ON public.yuno_items FOR SELECT TO authenticated USING ((auth.jwt()->>'is_anonymous')='true' AND private.yuno_account_id() IS NOT NULL);
CREATE POLICY yuno_items_insert ON public.yuno_items FOR INSERT TO authenticated WITH CHECK ((auth.jwt()->>'is_anonymous')='true' AND owner_id=private.yuno_account_id());
CREATE POLICY yuno_items_update ON public.yuno_items FOR UPDATE TO authenticated USING ((auth.jwt()->>'is_anonymous')='true' AND (owner_id=private.yuno_account_id() OR owner_id IS NULL)) WITH CHECK ((auth.jwt()->>'is_anonymous')='true' AND owner_id=private.yuno_account_id());
CREATE POLICY yuno_items_delete ON public.yuno_items FOR DELETE TO authenticated USING ((auth.jwt()->>'is_anonymous')='true' AND (owner_id=private.yuno_account_id() OR owner_id IS NULL));
CREATE POLICY yuno_profiles_read ON public.yuno_profiles FOR SELECT TO authenticated USING ((auth.jwt()->>'is_anonymous')='true' AND private.yuno_account_id() IS NOT NULL);
CREATE POLICY yuno_profiles_update ON public.yuno_profiles FOR UPDATE TO authenticated USING ((auth.jwt()->>'is_anonymous')='true' AND user_id=private.yuno_account_id()) WITH CHECK ((auth.jwt()->>'is_anonymous')='true' AND user_id=private.yuno_account_id());
CREATE POLICY yuno_messages_read ON public.yuno_messages FOR SELECT TO authenticated USING ((auth.jwt()->>'is_anonymous')='true' AND ((recipient_id IS NOT NULL AND (author_id=private.yuno_account_id() OR recipient_id=private.yuno_account_id())) OR (recipient_id IS NULL AND author_id=private.yuno_account_id())));
CREATE POLICY yuno_messages_insert ON public.yuno_messages FOR INSERT TO authenticated WITH CHECK ((auth.jwt()->>'is_anonymous')='true' AND author_id=private.yuno_account_id() AND recipient_id IS NOT NULL AND recipient_id<>author_id);
CREATE POLICY yuno_messages_delete ON public.yuno_messages FOR DELETE TO authenticated USING ((auth.jwt()->>'is_anonymous')='true' AND author_id=private.yuno_account_id());
CREATE OR REPLACE FUNCTION public.yuno_current_account() RETURNS uuid LANGUAGE sql SECURITY DEFINER SET search_path='' AS $$ SELECT private.yuno_account_id() $$;
CREATE OR REPLACE FUNCTION public.yuno_register(p_name text,p_pin text,p_phone text DEFAULT '') RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$
DECLARE v_uid uuid:=auth.uid();v_name text:=btrim(p_name);
BEGIN
 IF v_uid IS NULL OR (auth.jwt()->>'is_anonymous') IS DISTINCT FROM 'true' THEN RAISE EXCEPTION 'Anonymous sign-in required'; END IF;
 IF char_length(v_name) NOT BETWEEN 2 AND 40 OR p_pin !~ '^[0-9]{3}$' OR char_length(coalesce(p_phone,''))>30 THEN RAISE EXCEPTION 'Invalid account details'; END IF;
 IF EXISTS(SELECT 1 FROM private.yuno_sessions WHERE session_uid=v_uid) OR EXISTS(SELECT 1 FROM private.yuno_account_secrets WHERE account_id=v_uid) THEN RAISE EXCEPTION 'Account already exists; use login'; END IF;
 -- Legacy profile can be claimed only by the original anonymous auth.uid().
 INSERT INTO public.yuno_profiles(user_id,display_name,last_seen_at) VALUES(v_uid,v_name,now()) ON CONFLICT(user_id) DO UPDATE SET display_name=EXCLUDED.display_name,last_seen_at=now();
 INSERT INTO private.yuno_account_secrets(account_id,pin_hash,phone) VALUES(v_uid,extensions.crypt(p_pin,extensions.gen_salt('bf')),btrim(coalesce(p_phone,'')));
 INSERT INTO private.yuno_sessions(session_uid,account_id) VALUES(v_uid,v_uid);
 RETURN v_uid;
END $$;
CREATE OR REPLACE FUNCTION public.yuno_login(p_name text,p_pin text) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$
DECLARE v_uid uuid:=auth.uid();v_secret private.yuno_account_secrets%ROWTYPE;
BEGIN
 IF v_uid IS NULL OR (auth.jwt()->>'is_anonymous') IS DISTINCT FROM 'true' THEN RAISE EXCEPTION 'Anonymous sign-in required'; END IF;
 SELECT s.* INTO v_secret FROM private.yuno_account_secrets s JOIN public.yuno_profiles p ON p.user_id=s.account_id WHERE lower(btrim(p.display_name))=lower(btrim(p_name)) FOR UPDATE OF s;
 IF NOT FOUND THEN RETURN NULL; END IF;
 IF v_secret.locked_until>now() THEN RAISE EXCEPTION 'החשבון נעול זמנית; נסו שוב בעוד 15 דקות'; END IF;
 IF extensions.crypt(p_pin,v_secret.pin_hash) IS DISTINCT FROM v_secret.pin_hash THEN
  UPDATE private.yuno_account_secrets SET failures=CASE WHEN failures>=4 THEN 0 ELSE failures+1 END,locked_until=CASE WHEN failures>=4 THEN now()+interval '15 minutes' ELSE NULL END WHERE account_id=v_secret.account_id;
  RETURN NULL; -- RAISE would roll back the failed-attempt counter.
 END IF;
 UPDATE private.yuno_account_secrets SET failures=0,locked_until=NULL WHERE account_id=v_secret.account_id;
 INSERT INTO private.yuno_sessions(session_uid,account_id) VALUES(v_uid,v_secret.account_id) ON CONFLICT(session_uid) DO UPDATE SET account_id=EXCLUDED.account_id;
 RETURN v_secret.account_id;
END $$;
CREATE OR REPLACE FUNCTION public.yuno_my_phone() RETURNS text LANGUAGE sql SECURITY DEFINER SET search_path='' AS $$ SELECT phone FROM private.yuno_account_secrets WHERE account_id=private.yuno_account_id() $$;
CREATE OR REPLACE FUNCTION public.yuno_set_phone(p_phone text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$ BEGIN IF char_length(coalesce(p_phone,''))>30 THEN RAISE EXCEPTION 'Phone too long'; END IF; UPDATE private.yuno_account_secrets SET phone=btrim(coalesce(p_phone,'')) WHERE account_id=private.yuno_account_id(); IF NOT FOUND THEN RAISE EXCEPTION 'Login required'; END IF; END $$;
CREATE OR REPLACE FUNCTION public.yuno_change_pin(p_old text,p_new text) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$
DECLARE v_secret private.yuno_account_secrets%ROWTYPE;
BEGIN
 SELECT * INTO v_secret FROM private.yuno_account_secrets WHERE account_id=private.yuno_account_id() FOR UPDATE;
 IF NOT FOUND OR v_secret.locked_until>now() THEN RAISE EXCEPTION 'Account unavailable'; END IF;
 IF p_new !~ '^[0-9]{3}$' THEN RAISE EXCEPTION 'Three digits required'; END IF;
 IF extensions.crypt(p_old,v_secret.pin_hash) IS DISTINCT FROM v_secret.pin_hash THEN
  UPDATE private.yuno_account_secrets SET failures=CASE WHEN failures>=4 THEN 0 ELSE failures+1 END,locked_until=CASE WHEN failures>=4 THEN now()+interval '15 minutes' ELSE NULL END WHERE account_id=v_secret.account_id;
  RETURN false;
 END IF;
 UPDATE private.yuno_account_secrets SET pin_hash=extensions.crypt(p_new,extensions.gen_salt('bf')),failures=0,locked_until=NULL WHERE account_id=v_secret.account_id;
 RETURN true;
END $$;
CREATE OR REPLACE FUNCTION public.yuno_logout() RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path='' AS $$ DELETE FROM private.yuno_sessions WHERE session_uid=auth.uid() $$;
CREATE OR REPLACE FUNCTION public.yuno_admin_status() RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path='' AS $$ SELECT private.yuno_is_admin() $$;
CREATE OR REPLACE FUNCTION public.yuno_wipe_all() RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$
BEGIN
 IF NOT private.yuno_is_admin() THEN RAISE EXCEPTION 'Admin account required'; END IF;
 DELETE FROM public.yuno_messages;
 DELETE FROM public.yuno_items;
 DELETE FROM public.yuno_profiles; -- Cascades to all account secrets, sessions and admin grants.
END $$;
CREATE OR REPLACE FUNCTION public.yuno_export_all() RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$
BEGIN
 IF NOT private.yuno_is_admin() THEN RAISE EXCEPTION 'Admin account required'; END IF;
 RETURN jsonb_build_object('items',(SELECT coalesce(jsonb_agg(to_jsonb(i) ORDER BY i.updated_at DESC),'[]'::jsonb) FROM public.yuno_items i),'profiles',(SELECT coalesce(jsonb_agg(jsonb_build_object('user_id',p.user_id,'display_name',p.display_name,'phone',s.phone,'created_at',p.created_at,'last_seen_at',p.last_seen_at)),'[]'::jsonb) FROM public.yuno_profiles p LEFT JOIN private.yuno_account_secrets s ON s.account_id=p.user_id),'messages',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY m.created_at),'[]'::jsonb) FROM public.yuno_messages m));
END $$;
REVOKE ALL ON FUNCTION public.yuno_current_account(),public.yuno_register(text,text,text),public.yuno_login(text,text),public.yuno_my_phone(),public.yuno_set_phone(text),public.yuno_change_pin(text,text),public.yuno_logout(),public.yuno_admin_status(),public.yuno_wipe_all(),public.yuno_export_all() FROM PUBLIC,anon;
GRANT EXECUTE ON FUNCTION public.yuno_current_account(),public.yuno_register(text,text,text),public.yuno_login(text,text),public.yuno_my_phone(),public.yuno_set_phone(text),public.yuno_change_pin(text,text),public.yuno_logout(),public.yuno_admin_status(),public.yuno_wipe_all(),public.yuno_export_all() TO authenticated;
COMMIT;
NOTIFY pgrst,'reload schema';
-- After registering the actual administrator, run SEPARATELY in SQL Editor with the exact account UUID shown in the Users screen:
-- INSERT INTO private.yuno_admins(account_id) VALUES ('YOUR-ACCOUNT-UUID');
-- Never assign admin rights based on the unverified display name. A 3-digit PIN is NOT secure for sensitive data.
