CREATE TABLE account
(
    id       BIGINT  NOT NULL,
    username VARCHAR(255),
    email    VARCHAR(255),
    age      INTEGER NOT NULL,
    password VARCHAR(255),
    CONSTRAINT pk_account PRIMARY KEY (id)
);

CREATE TABLE account_roles
(
    role_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    CONSTRAINT pk_account_roles PRIMARY KEY (role_id, user_id)
);

CREATE TABLE resources
(
    id            BIGINT  NOT NULL,
    resource_name VARCHAR(255),
    http_method   VARCHAR(255),
    order_num     INTEGER NOT NULL,
    resource_type VARCHAR(255),
    CONSTRAINT pk_resources PRIMARY KEY (id)
);

CREATE TABLE role
(
    role_id   BIGINT NOT NULL,
    role_name VARCHAR(255),
    role_desc VARCHAR(255),
    CONSTRAINT pk_role PRIMARY KEY (role_id)
);

CREATE TABLE role_resources
(
    resource_id BIGINT NOT NULL,
    role_id     BIGINT NOT NULL,
    CONSTRAINT pk_role_resources PRIMARY KEY (resource_id, role_id)
);

ALTER TABLE account_roles
    ADD CONSTRAINT fk_accrol_on_account FOREIGN KEY (user_id) REFERENCES account (id);

ALTER TABLE account_roles
    ADD CONSTRAINT fk_accrol_on_role FOREIGN KEY (role_id) REFERENCES role (role_id);

ALTER TABLE role_resources
    ADD CONSTRAINT fk_rolres_on_resources FOREIGN KEY (resource_id) REFERENCES resources (id);

ALTER TABLE role_resources
    ADD CONSTRAINT fk_rolres_on_role FOREIGN KEY (role_id) REFERENCES role (role_id);