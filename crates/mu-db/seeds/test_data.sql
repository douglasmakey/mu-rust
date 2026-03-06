INSERT INTO accounts (username, password_hash, is_banned, banned_until)
VALUES
    -- password = "test"  (plain low-level test account)
    ('test',   '$2b$12$FJ7ROOOr1bXLzVoXztwXOeOnqpKjYNvU3lCsy8ecyHSORTCjhvEfy', FALSE, NULL),
    -- password = "testgm"  (game-master account)
    ('testgm', '$2b$12$NaP1QiM9NbcIDsmcEYgS1uJYfJdZ5qKdeKP3mVw8Eqv.lhqnN1omy', FALSE, NULL),
    -- password = "banned"  (permanently banned account — for testing ban flow)
    ('banned', '$2b$12$LVu4hr2weD/lIL9P6tmPFOGYyFQ.D8sU2mAwZRPC7s1lviK6pj/sy', TRUE,  NULL),
    -- password = "banned"  (temp-banned — expires far in future for testing)
    ('tmpban', '$2b$12$LVu4hr2weD/lIL9P6tmPFOGYyFQ.D8sU2mAwZRPC7s1lviK6pj/sy', TRUE,  NOW() + INTERVAL '30 days')
ON CONFLICT (username) DO NOTHING;

-- ---------------------------------------------------------------------------
-- Characters for "test" — one of each basic class at level 1, map Lorencia
--   slot 0 = Dark Knight   (testDk)
--   slot 1 = Dark Wizard   (testDw)
--   slot 2 = Fairy Elf     (testElf)
--   slot 3 = Dark Lord     (testDl)
-- ---------------------------------------------------------------------------
INSERT INTO characters (account_id, slot, name, class, level, map_id, pos_x, pos_y, experience, hero_state)
SELECT a.id, 0, 'testDk',  4, 1, 0, 135, 127, 0, 0 FROM accounts a WHERE a.username = 'test'
ON CONFLICT (account_id, slot) DO NOTHING;

INSERT INTO characters (account_id, slot, name, class, level, map_id, pos_x, pos_y, experience, hero_state)
SELECT a.id, 1, 'testDw',  0, 1, 0, 135, 127, 0, 0 FROM accounts a WHERE a.username = 'test'
ON CONFLICT (account_id, slot) DO NOTHING;

INSERT INTO characters (account_id, slot, name, class, level, map_id, pos_x, pos_y, experience, hero_state)
SELECT a.id, 2, 'testElf', 8, 1, 0, 135, 127, 0, 0 FROM accounts a WHERE a.username = 'test'
ON CONFLICT (account_id, slot) DO NOTHING;

INSERT INTO characters (account_id, slot, name, class, level, map_id, pos_x, pos_y, experience, hero_state)
SELECT a.id, 3, 'testDl', 16, 1, 0, 135, 127, 0, 0 FROM accounts a WHERE a.username = 'test'
ON CONFLICT (account_id, slot) DO NOTHING;

-- ---------------------------------------------------------------------------
-- Characters for "testgm" — high-level GameMaster characters
-- Level 300 — exp = 377,963,080  (10*(300+8)*(299)^2)
-- ---------------------------------------------------------------------------
INSERT INTO characters (account_id, slot, name, class, level, map_id, pos_x, pos_y, experience, hero_state)
SELECT a.id, 0, 'gmDk',  4, 300, 0, 135, 127, 377963080, 0 FROM accounts a WHERE a.username = 'testgm'
ON CONFLICT (account_id, slot) DO NOTHING;

INSERT INTO characters (account_id, slot, name, class, level, map_id, pos_x, pos_y, experience, hero_state)
SELECT a.id, 1, 'gmDw',  0, 300, 0, 135, 127, 377963080, 0 FROM accounts a WHERE a.username = 'testgm'
ON CONFLICT (account_id, slot) DO NOTHING;
