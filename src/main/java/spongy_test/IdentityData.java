package spongy_test;

import java.io.Serializable;

public class IdentityData implements Serializable {

    private String did;

    public IdentityData() {}

    public IdentityData(String did) {
        this.did = did;
    }

    public String getDid() {
        return did;
    }

}
