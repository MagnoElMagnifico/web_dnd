begin;

------------------------------------------------------------
-------- USERS ---------------------------------------------
------------------------------------------------------------

create table if not exists users (
    user_name text
        primary key
        not null,
    passwd_hash text
        not null
    -- cookie text -- TODO: HTTP Autentitation
);


------------------------------------------------------------
-------- CAMPAIGNS -----------------------------------------
------------------------------------------------------------

create table if not exists campaigns (
    campaign_name text
        primary key
        not null,
    dm text references users (user_name)
        on delete restrict -- if deleted, no one else can be DM
        on update cascade
        not null
);

-- TODO: not (campaigns.dm = campaign_players.user_name and
--       campaigns.campaign_name = campaign_players.campaign_name)
create table if not exists campaign_players (
    campaign_name text references campaigns (campaign_name)
        on delete cascade
        on update cascade
        not null,
    user_name text references users (user_name)
        on delete cascade
        on update cascade
        not null,
    character_name text references player_characters (character_name)
        on delete cascade
        on update cascade
        not null
        unique, -- one character can only be used in one campaign
    turn integer
        default 0,
        -- autoincrement, TODO: invalid syntax. Only applies to primary keys
    primary key (campaign_name, user_name),
    unique (campaign_name, user_name, turn)
);


------------------------------------------------------------
-------- MAPS ----------------------------------------------
------------------------------------------------------------

create table if not exists maps (
    map_name text
        primary key
        not null,
    image_atlas blob
);

create table if not exists tiles (
    position_x integer not null,
    position_y integer not null,
    map_name text references maps (map_name)
        on delete cascade
        on update cascade
        not null,
    character_name text references characters (character_name)
        on delete set null
        on update cascade
        default null,
    tile_type text
        check (tile_type in ('floor', 'wall', 'stairs', 'furniture')) -- TODO: more tile types
        default 'floor'
        not null,
    primary key (map_name, position_x, position_y)
);

create table if not exists campaign_maps (
    campaign_name text references campaigns (campaign_name)
        on delete cascade
        on update cascade
        not null,
    map_name text references maps (map_name)
        on delete cascade
        on update cascade
        not null,
    primary key (campaign_name, map_name)
);


------------------------------------------------------------
-------- CHARACTERS ----------------------------------------
------------------------------------------------------------

create table if not exists characters (
    character_name text
        primary key
        not null,
    avatar blob
        not null,
    max_move_dist integer
        check (max_move_dist > 0)
        not null
);

create table if not exists character_resistances (
    character_name text references characters (character_name)
        on delete cascade
        on update cascade
        not null,
    resistance_type text
        check (resistance_type in ('poison', 'fire')) -- TODO: more resistance types
        not null,
    primary key (character_name, resistance_type)
);

create table if not exists player_characters (
    character_name text references characters (character_name)
        on delete cascade
        on update cascade
        primary key
        not null,
    health integer
        check (health >= 0)
        not null
);

create table if not exists character_owners (
    user_name text references users (user_name)
        on delete cascade
        on update cascade
        not null,
    character_name text references player_characters (character_name)
        on delete cascade
        on update cascade
        not null,
    primary key (user_name, character_name)
);

create table if not exists enemies (
    character_name text references characters (character_name)
        on delete cascade
        on update cascade
        primary key
        not null,
    health integer
        check (health >= 0)
        not null
);


------------------------------------------------------------
-------- ATTACKS -------------------------------------------
------------------------------------------------------------

create table if not exists attacks (
    attack_name text
        primary key
        not null,
    damage integer
        check (damage > 0)
        not null,
    distance real
        check (distance >= 0)
        not null
);

create table if not exists spells (
    attack_name text references attacks (attack_name)
        on delete cascade
        on update cascade
        primary key
        not null,
    area real
        check (area > 0)
        not null
);

create table if not exists attack_damage_types (
    attack_name text references attacks (attack_name)
        on delete cascade
        on update cascade
        not null,
    damage_type text
        check (damage_type in ('poison', 'fire')) -- TODO: more damage types
        not null,
    primary key (attack_name, damage_type)
);

create table if not exists character_attacks (
    character_name text references characters (character_name)
        on delete cascade
        on update cascade
        not null,
    attack_name text references attacks (attack_name)
        on delete cascade
        on update cascade
        not null,
    primary key (character_name, attack_name)
);

end;
